import * as vscode from 'vscode';

const OSV_API_URL = 'https://api.osv.dev/v1/query';
const VULN_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const OSV_CONCURRENCY = 10; // max parallel OSV queries

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

// ---- OSV API + cache types ----

interface OsvPackage {
  name: string;
  ecosystem: string;
}

interface OsvQueryRequest {
  version: string;
  package: OsvPackage;
}

interface OsvSeverity {
  type: string;
  score?: string;
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: OsvSeverity[];
}

interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
}

interface CacheEntry {
  vulns?: OsvVulnerability[];
  fetchedAt: number;
}

const vulnCache = new Map<string, CacheEntry>();

let statusBarItem: vscode.StatusBarItem | undefined;

// Used for building diagnostics
interface CheckItem {
  name: string;
  version: string;
  isDirect: boolean;
  range: vscode.Range;
}

export function activate(context: vscode.ExtensionContext) {
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection('cerbe-npm-vuln-checker');
  context.subscriptions.push(diagnosticCollection);

  // Status bar item
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.text = '$(shield) NPM Vuln: Ready';
  statusBarItem.tooltip =
    'Scan package.json for known vulnerabilities with OSV.dev';
  statusBarItem.command = 'cerbe.scanDependencies';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Command (still available manually)
  const scanCommand = vscode.commands.registerCommand(
    'cerbe.scanDependencies',
    async () => {
      await scanWorkspaceForVulns(diagnosticCollection);
    }
  );
  context.subscriptions.push(scanCommand);

  // 1. Run automatically when workspace is opened
  if (vscode.workspace.workspaceFolders?.length) {
    scanWorkspaceForVulns(diagnosticCollection);
  }

  // 2. Watch for modifications to package.json
  const pkgWatcher = vscode.workspace.createFileSystemWatcher('**/package.json');

  pkgWatcher.onDidChange(async () => {
    await scanWorkspaceForVulns(diagnosticCollection);
  });

  pkgWatcher.onDidCreate(async () => {
    await scanWorkspaceForVulns(diagnosticCollection);
  });

  pkgWatcher.onDidDelete(() => {
    diagnosticCollection.clear();
    if (statusBarItem) {
      statusBarItem.text = '$(shield) NPM Vuln: No package.json';
      statusBarItem.tooltip = 'No package.json found in this workspace';
    }
  });

  context.subscriptions.push(pkgWatcher);

  // 3. Watch for lockfile changes (npm / yarn / pnpm)
  const lockWatchers = [
    vscode.workspace.createFileSystemWatcher('**/package-lock.json'),
    vscode.workspace.createFileSystemWatcher('**/yarn.lock'),
    vscode.workspace.createFileSystemWatcher('**/pnpm-lock.yaml')
  ];

  for (const watcher of lockWatchers) {
    watcher.onDidChange(async () => {
      await scanWorkspaceForVulns(diagnosticCollection);
    });
    watcher.onDidCreate(async () => {
      await scanWorkspaceForVulns(diagnosticCollection);
    });
    watcher.onDidDelete(async () => {
      await scanWorkspaceForVulns(diagnosticCollection);
    });
    context.subscriptions.push(watcher);
  }
}

export function deactivate() {
  // nothing special
}

// ---- Main scan logic ----

async function scanWorkspaceForVulns(
  diagnostics: vscode.DiagnosticCollection
) {
  diagnostics.clear();

  if (statusBarItem) {
    statusBarItem.text = '$(sync~spin) NPM Vuln: Scanning...';
    statusBarItem.tooltip = 'Scanning dependencies with OSV.dev...';
    statusBarItem.show();
  }

  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showWarningMessage(
      'NPM Vulnerability Checker: No workspace folder is open.'
    );
    if (statusBarItem) {
      statusBarItem.text = '$(shield) NPM Vuln: No workspace';
      statusBarItem.tooltip = 'Open a folder to scan for vulnerabilities';
    }
    return;
  }

  // Look for the root package.json (first match)
  const [pkgUri] = await vscode.workspace.findFiles(
    'package.json',
    '**/node_modules/**',
    1
  );

  if (!pkgUri) {
    vscode.window.showWarningMessage(
      'NPM Vulnerability Checker: No package.json found in the workspace root.'
    );
    if (statusBarItem) {
      statusBarItem.text = '$(shield) NPM Vuln: No package.json';
      statusBarItem.tooltip = 'No package.json found in the workspace root';
    }
    return;
  }

  try {
    const doc = await vscode.workspace.openTextDocument(pkgUri);
    const text = doc.getText();
    const pkgJson = JSON.parse(text) as PackageJson;

    const directDeps = {
      ...(pkgJson.dependencies ?? {}),
      ...(pkgJson.devDependencies ?? {})
    };

    const directEntries = Object.entries(directDeps);
    if (directEntries.length === 0) {
      vscode.window.showInformationMessage(
        'NPM Vulnerability Checker: No dependencies found in package.json.'
      );
      if (statusBarItem) {
        statusBarItem.text = '$(shield) NPM Vuln: 0 deps';
        statusBarItem.tooltip = 'No dependencies found in package.json';
      }
      return;
    }

    // Try to read transitive deps from any lockfile (npm, yarn, pnpm)
    const lockDeps = await readLockfileDependencies();

    // Build the list of packages to check (direct + transitive)
    const checkMap = new Map<string, CheckItem>();

    // Direct deps: use lockfile version if available, otherwise normalized range
    for (const [name, versionRange] of directEntries) {
      const lockVersion = lockDeps?.get(name);
      const normalizedFromPkg = normalizeVersion(versionRange);
      const versionToUse = lockVersion ?? normalizedFromPkg;

      if (!versionToUse) {
        continue;
      }

      const key = cacheKey(name, versionToUse);
      if (checkMap.has(key)) {
        continue;
      }

      const range = findDependencyRangeInPackageJson(doc, name);

      checkMap.set(key, {
        name,
        version: versionToUse,
        isDirect: true,
        range
      });
    }

    // Transitive deps: from lock files only
    if (lockDeps) {
      const firstLineRange = doc.lineAt(0).range;
      for (const [name, version] of lockDeps.entries()) {
        const normalized = normalizeVersion(version) ?? version;
        if (!normalized) continue;

        const key = cacheKey(name, normalized);
        if (checkMap.has(key)) {
          continue; // already covered as direct or seen
        }

        checkMap.set(key, {
          name,
          version: normalized,
          isDirect: false,
          // For transitive-only deps, attach diagnostic to first line of package.json
          range: firstLineRange
        });
      }
    }

    const checkItems = Array.from(checkMap.values());
    if (checkItems.length === 0) {
      vscode.window.showInformationMessage(
        'NPM Vulnerability Checker: No dependencies to scan.'
      );
      if (statusBarItem) {
        statusBarItem.text = '$(shield) NPM Vuln: 0 deps';
        statusBarItem.tooltip = 'No dependencies to scan';
      }
      return;
    }

    // Parallel OSV queries with simple batching
    const results = new Map<string, OsvVulnerability[] | undefined>();

    for (let i = 0; i < checkItems.length; i += OSV_CONCURRENCY) {
      const slice = checkItems.slice(i, i + OSV_CONCURRENCY);

      const promises = slice.map(async (item) => {
        const vulns = await queryOsvForPackage(item.name, item.version);
        const key = cacheKey(item.name, item.version);
        results.set(key, vulns);
      });

      await Promise.all(promises);
    }

    const allDiagnostics: vscode.Diagnostic[] = [];

    for (const item of checkItems) {
      const key = cacheKey(item.name, item.version);
      const vulns = results.get(key);
      if (!vulns || vulns.length === 0) {
        continue;
      }

      const first = vulns[0];
      const count = vulns.length;

      const messageParts: string[] = [];
      messageParts.push(
        `${item.name}@${item.version} has ${count} known vulnerability${
          count > 1 ? 'ies' : 'y'
        } in OSV.dev.`
      );
      if (!item.isDirect) {
        messageParts.push('(transitive dependency)');
      }
      if (first.summary) {
        messageParts.push(`Example: ${first.summary}`);
      }
      if (first.id) {
        messageParts.push(`(e.g. ${first.id})`);
      }

      const message = messageParts.join(' ');

      const diagnostic = new vscode.Diagnostic(
        item.range,
        message,
        vscode.DiagnosticSeverity.Warning
      );
      diagnostic.source = 'OSV.dev';

      if (first.id) {
        diagnostic.code = {
          value: first.id,
          target: vscode.Uri.parse(
            `https://osv.dev/vulnerability/${first.id}`
          )
        };
      }

      allDiagnostics.push(diagnostic);
    }

    diagnostics.set(pkgUri, allDiagnostics);

    const transitiveIssueCount = allDiagnostics.filter((d) =>
      d.message.includes('(transitive dependency)')
    ).length;
    const directIssueCount = allDiagnostics.length - transitiveIssueCount;

    if (allDiagnostics.length === 0) {
      vscode.window.showInformationMessage(
        'NPM Vulnerability Checker: No known vulnerabilities found for listed dependencies (according to OSV.dev).'
      );
      if (statusBarItem) {
        statusBarItem.text = '$(shield) NPM Vuln: 0 issues';
        statusBarItem.tooltip =
          'No known vulnerabilities found for listed dependencies';
      }
    } else {
      vscode.window.showWarningMessage(
        `NPM Vulnerability Checker: Found ${allDiagnostics.length} vulnerable dependency entries (direct + transitive). Check package.json and the Problems panel.`
      );
      if (statusBarItem) {
        statusBarItem.text = `$(shield) NPM Vuln: ${allDiagnostics.length} issue${
          allDiagnostics.length === 1 ? '' : 's'
        }`;
        statusBarItem.tooltip = `Direct issues: ${directIssueCount}, transitive issues: ${transitiveIssueCount}`;
      }
    }
  } catch (err: any) {
    console.error('Error scanning dependencies', err);
    vscode.window.showErrorMessage(
      `NPM Vulnerability Checker: Failed to scan dependencies: ${err?.message ?? String(
        err
      )}`
    );
    if (statusBarItem) {
      statusBarItem.text = '$(error) NPM Vuln: Error';
      statusBarItem.tooltip = 'Click to retry scanning dependencies';
    }
  }
}

// ---- Lockfile helpers (transitive deps) ----

/**
 * Reads any available lockfile (npm, yarn, pnpm) and flattens all dependencies
 * (including transitive) into a map of name -> version.
 */
async function readLockfileDependencies(): Promise<
  Map<string, string> | undefined
> {
  const acc = new Map<string, string>();

  await readNpmLockInto(acc);
  await readYarnLockInto(acc);
  await readPnpmLockInto(acc);

  return acc.size ? acc : undefined;
}

// npm: package-lock.json
async function readNpmLockInto(acc: Map<string, string>): Promise<void> {
  const [lockUri] = await vscode.workspace.findFiles(
    'package-lock.json',
    '**/node_modules/**',
    1
  );
  if (!lockUri) return;

  try {
    const doc = await vscode.workspace.openTextDocument(lockUri);
    const text = doc.getText();
    const lockJson = JSON.parse(text) as any;

    if (lockJson.dependencies && typeof lockJson.dependencies === 'object') {
      collectDepsFromNpmLock(lockJson.dependencies, acc);
    }
  } catch (err) {
    console.warn('Failed to read package-lock.json:', err);
  }
}

function collectDepsFromNpmLock(
  deps: Record<string, any>,
  acc: Map<string, string>
) {
  for (const [name, info] of Object.entries(deps)) {
    if (!info || typeof info !== 'object') continue;

    const version = typeof (info as any).version === 'string'
      ? (info as any).version
      : undefined;
    if (version && !acc.has(name)) {
      acc.set(name, version);
    }

    if ((info as any).dependencies && typeof (info as any).dependencies === 'object') {
      collectDepsFromNpmLock((info as any).dependencies as Record<string, any>, acc);
    }
  }
}

// yarn: yarn.lock (classic)
async function readYarnLockInto(acc: Map<string, string>): Promise<void> {
  const [yarnUri] = await vscode.workspace.findFiles(
    'yarn.lock',
    '**/node_modules/**',
    1
  );
  if (!yarnUri) return;

  try {
    const doc = await vscode.workspace.openTextDocument(yarnUri);
    const text = doc.getText();
    parseYarnLock(text, acc);
  } catch (err) {
    console.warn('Failed to read yarn.lock:', err);
  }
}

/**
 * Very lightweight yarn.lock parser (v1-style).
 * Extracts name + version from stanzas like:
 *
 * "pkg-name@^1.0.0":
 *   version "1.2.3"
 */
function parseYarnLock(text: string, acc: Map<string, string>) {
  const lines = text.split(/\r?\n/);
  let currentNames: string[] = [];
  let currentVersion: string | undefined;

  const flush = () => {
    if (!currentVersion) return;
    for (const spec of currentNames) {
      const name = extractNameFromYarnSpec(spec);
      if (!name) continue;
      if (!acc.has(name)) {
        acc.set(name, currentVersion);
      }
    }
    currentNames = [];
    currentVersion = undefined;
  };

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();

    // New stanza key line: e.g. "pkg@^1.0.0", "pkg@~1.1.0":
    if (line.endsWith(':') && !line.startsWith('  ') && line !== 'resolution:') {
      // Flush previous stanza
      flush();

      const keyPart = line.slice(0, -1).trim(); // remove trailing :
      // Split multi-spec line: "pkg@^1.0.0", "pkg@~1.1.0"
      const specs = keyPart.split(/,\s*/).map((s) => s.replace(/^"|"$/g, ''));
      currentNames = specs;
    } else if (line.startsWith('version ')) {
      // version "1.2.3"
      const match = line.match(/version\s+"([^"]+)"/);
      if (match) {
        currentVersion = match[1];
      }
    } else if (!line.startsWith(' ') && line.trim() === '') {
      // Blank line -> stanza separator
      flush();
    }
  }

  // Flush last stanza
  flush();
}

function extractNameFromYarnSpec(spec: string): string | undefined {
  // Examples:
  // "lodash@^4.17.21" -> lodash
  // "@scope/pkg@^1.0.0" -> @scope/pkg
  // "pkg@npm:1.2.3" -> pkg
  // "@scope/pkg@npm:^1.0.0" -> @scope/pkg

  if (!spec) return undefined;

  // Scoped package: starts with "@"
  if (spec.startsWith('@')) {
    // Find second "@"
    const secondAt = spec.indexOf('@', 1);
    if (secondAt === -1) return spec; // odd, but fallback
    return spec.slice(0, secondAt);
  }

  // Non-scoped: name is before first "@"
  const atIndex = spec.indexOf('@');
  if (atIndex === -1) return spec;
  return spec.slice(0, atIndex);
}

// pnpm: pnpm-lock.yaml
async function readPnpmLockInto(acc: Map<string, string>): Promise<void> {
  const [pnpmUri] = await vscode.workspace.findFiles(
    'pnpm-lock.yaml',
    '**/node_modules/**',
    1
  );
  if (!pnpmUri) return;

  try {
    const doc = await vscode.workspace.openTextDocument(pnpmUri);
    const text = doc.getText();
    parsePnpmLock(text, acc);
  } catch (err) {
    console.warn('Failed to read pnpm-lock.yaml:', err);
  }
}

/**
 * Very lightweight pnpm-lock.yaml parser.
 * We look for lines under "packages:" that look like:
 *
 *   /name/1.2.3:
 *   /@scope/name/4.5.6:
 *
 * and extract name + version from the path.
 */
function parsePnpmLock(text: string, acc: Map<string, string>) {
  const lines = text.split(/\r?\n/);
  let inPackagesSection = false;

  for (const rawLine of lines) {
    const line = rawLine.replace(/\t/g, '  '); // normalize tabs to spaces

    if (!inPackagesSection) {
      if (line.trim() === 'packages:') {
        inPackagesSection = true;
      }
      continue;
    }

    // packages section ends when unindented line without leading spaces appears
    if (!line.startsWith('  ') && line.trim().length > 0) {
      // leaving packages section
      inPackagesSection = false;
      continue;
    }

    // Look for keys like "  /name/1.2.3:" or "  /@scope/name/1.2.3:"
    const match = line.match(/^\s{2}\/(.+?)\/([^/:\s]+):\s*$/);
    if (!match) continue;

    const fullName = match[1]; // may be "@scope/name" or "name"
    const version = match[2];

    if (!acc.has(fullName)) {
      acc.set(fullName, version);
    }
  }
}

// ---- OSV API + cache helpers ----

function cacheKey(name: string, version: string): string {
  return `${name}@${version}`;
}

/**
 * Query OSV.dev for a specific npm package version, with background caching.
 */
async function queryOsvForPackage(
  name: string,
  version: string
): Promise<OsvVulnerability[] | undefined> {
  const key = cacheKey(name, version);
  const now = Date.now();

  const cached = vulnCache.get(key);
  if (cached && now - cached.fetchedAt < VULN_CACHE_TTL_MS) {
    // Fresh cache hit
    return cached.vulns;
  }

  const body: OsvQueryRequest = {
    version,
    package: {
      name,
      ecosystem: 'npm'
    }
  };

  try {
    const res = await fetch(OSV_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      console.warn(
        `OSV.dev query failed for ${name}@${version}: ${res.status} ${res.statusText}`
      );
      // If we have stale cache, use it as a fallback
      return cached?.vulns;
    }

    const data = (await res.json()) as OsvQueryResponse;
    const vulns = data.vulns;

    vulnCache.set(key, {
      vulns,
      fetchedAt: now
    });

    return vulns;
  } catch (err) {
    console.warn(`OSV.dev query error for ${name}@${version}:`, err);
    // On network/other errors, fall back to stale cache if present
    return cached?.vulns;
  }
}

// ---- Utility functions ----

/**
 * Best-effort normalization:
 *  - strips leading ^ or ~
 *  - returns undefined for non-semver-ish values (git urls, file: etc.)
 */
function normalizeVersion(raw: string): string | undefined {
  const trimmed = raw.trim();

  // Basic skip for dist-tags and non-semver refs
  if (
    trimmed.startsWith('git+') ||
    trimmed.startsWith('file:') ||
    trimmed.startsWith('http://') ||
    trimmed.startsWith('https://') ||
    trimmed === 'latest'
  ) {
    return undefined;
  }

  // Strip common range prefixes
  const stripped = trimmed.replace(/^[~^]/, '');

  // Very loose semver-ish check: 1.2.3 or 0.0.0-security etc.
  if (!/\d+\.\d+/.test(stripped)) {
    return undefined;
  }

  return stripped;
}

/**
 * Finds the range in package.json covering `"name": "version"` for diagnostics.
 * If not found, falls back to the first line of the file.
 */
function findDependencyRangeInPackageJson(
  doc: vscode.TextDocument,
  depName: string
): vscode.Range {
  const text = doc.getText();
  const regex = new RegExp(
    `"${escapeRegex(depName)}"\\s*:\\s*"(.*?)"`,
    'g'
  );
  const match = regex.exec(text);
  if (!match) {
    // Fallback: first line
    const firstLine = doc.lineAt(0);
    return firstLine.range;
  }

  const startOffset = match.index;
  const endOffset = match.index + match[0].length;

  const startPos = doc.positionAt(startOffset);
  const endPos = doc.positionAt(endOffset);
  return new vscode.Range(startPos, endPos);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
