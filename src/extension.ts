import * as vscode from 'vscode';

const OSV_API_URL = 'https://api.osv.dev/v1/query';
const VULN_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const OSV_CONCURRENCY = 10; // max parallel OSV queries
const DIAGNOSTIC_COLLECTION_ID = 'cerbe-npm-vuln-checker';

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
let scanInProgress = false;
let scanQueued = false;

// Used for building diagnostics
interface CheckItem {
  name: string;
  version: string;
  isDirect: boolean;
  range: vscode.Range;
  uri: vscode.Uri;
}

export const activate = (context: vscode.ExtensionContext) => {
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION_ID);
  context.subscriptions.push(diagnosticCollection);

  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.text = '$(shield) Cerbe Ready';
  statusBarItem.tooltip =
    'Scan package.json for known vulnerabilities with OSV.dev';
  statusBarItem.command = 'cerbe.scanDependencies';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  const triggerScan = () => {
    void requestScan(diagnosticCollection);
  };

  const scanCommand = vscode.commands.registerCommand(
    'cerbe.scanDependencies',
    triggerScan
  );
  context.subscriptions.push(scanCommand);

  if (vscode.workspace.workspaceFolders?.length) {
    triggerScan();
  }

  const pkgWatcher = vscode.workspace.createFileSystemWatcher('**/package.json');

  pkgWatcher.onDidChange(triggerScan);

  pkgWatcher.onDidCreate(triggerScan);

  pkgWatcher.onDidDelete(() => {
    diagnosticCollection.clear();
    updateStatusBar(
      '$(shield) Cerbe No package.json',
      'No package.json found in this workspace'
    );
  });

  context.subscriptions.push(pkgWatcher);

  const lockWatchers = [
    vscode.workspace.createFileSystemWatcher('**/package-lock.json'),
    vscode.workspace.createFileSystemWatcher('**/yarn.lock'),
    vscode.workspace.createFileSystemWatcher('**/pnpm-lock.yaml')
  ];

  lockWatchers.forEach((watcher) => {
    watcher.onDidChange(triggerScan);
    watcher.onDidCreate(triggerScan);
    watcher.onDidDelete(triggerScan);
    context.subscriptions.push(watcher);
  });
};

export const deactivate = () => {
  // nothing special
};

// ---- Main scan logic ----

const requestScan = async (diagnostics: vscode.DiagnosticCollection) => {
  if (scanInProgress) {
    scanQueued = true;
    return;
  }

  scanInProgress = true;
  try {
    await scanWorkspaceForVulns(diagnostics);
  } finally {
    scanInProgress = false;
    if (scanQueued) {
      scanQueued = false;
      void requestScan(diagnostics);
    }
  }
};

const scanWorkspaceForVulns = async (
  diagnostics: vscode.DiagnosticCollection
) => {
  diagnostics.clear();

  updateStatusBar(
    '$(sync~spin) Cerbe Scanning...',
    'Scanning dependencies with OSV.dev...'
  );

  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showWarningMessage('Cerbe: No workspace folder is open.');
    updateStatusBar(
      '$(shield) Cerbe No workspace',
      'Open a folder to scan for vulnerabilities'
    );
    return;
  }

  const pkgUris = await vscode.workspace.findFiles(
    '**/package.json',
    '**/node_modules/**'
  );

  if (!pkgUris || pkgUris.length === 0) {
    vscode.window.showWarningMessage(
      'Cerbe: No package.json files found in the workspace.'
    );
    updateStatusBar(
      '$(shield) Cerbe No package.json',
      'No package.json found in this workspace'
    );
    return;
  }

  try {
    const lockDeps = await readLockfileDependencies();

    const checkItems: CheckItem[] = [];
    const uniqueQueries = new Map<string, { name: string; version: string }>();
    const docsByUri = new Map<string, vscode.TextDocument>();

    await Promise.all(
      pkgUris.map(async (pkgUri) => {
        const doc = await vscode.workspace.openTextDocument(pkgUri);
        docsByUri.set(pkgUri.toString(), doc);

        const pkgJson = safeParsePackageJson(doc);
        if (!pkgJson) {
          return;
        }

        const directDeps = {
          ...(pkgJson.dependencies ?? {}),
          ...(pkgJson.devDependencies ?? {})
        };

        const directEntries = Object.entries(directDeps);
        if (directEntries.length === 0) {
          return;
        }

        directEntries.forEach(([name, versionRange]) => {
          const lockVersion = lockDeps?.get(name);
          const normalizedFromPkg = normalizeVersion(versionRange);
          const versionToUse = lockVersion ?? normalizedFromPkg;

          if (!versionToUse) {
            return;
          }

          const range = findDependencyRangeInPackageJson(doc, name);
          const item: CheckItem = {
            name,
            version: versionToUse,
            isDirect: true,
            range,
            uri: pkgUri
          };
          checkItems.push(item);

          const key = cacheKey(name, versionToUse);
          uniqueQueries.set(key, { name, version: versionToUse });
        });
      })
    );

    if (lockDeps && pkgUris.length > 0) {
      const primaryUri = pkgUris[0];
      const primaryDoc =
        docsByUri.get(primaryUri.toString()) ??
        (await vscode.workspace.openTextDocument(primaryUri));

      const firstLineRange = primaryDoc.lineAt(0).range;

      Array.from(lockDeps.entries()).forEach(([name, version]) => {
        const normalized = normalizeVersion(version) ?? version;
        if (!normalized) {
          return;
        }

        const item: CheckItem = {
          name,
          version: normalized,
          isDirect: false,
          range: firstLineRange,
          uri: primaryUri
        };
        checkItems.push(item);

        const key = cacheKey(name, normalized);
        uniqueQueries.set(key, { name, version: normalized });
      });
    }

    if (checkItems.length === 0) {
      vscode.window.showInformationMessage('Cerbe: No dependencies to scan.');
      updateStatusBar('$(shield) Cerbe 0 deps', 'No dependencies to scan');
      return;
    }

    const results = new Map<string, OsvVulnerability[] | undefined>();
    const uniqueList = Array.from(uniqueQueries.values());
    const chunkCount = Math.ceil(uniqueList.length / OSV_CONCURRENCY);
    const chunks = Array.from({ length: chunkCount }, (_, idx) =>
      uniqueList.slice(
        idx * OSV_CONCURRENCY,
        (idx + 1) * OSV_CONCURRENCY
      )
    );

    await chunks.reduce(
      async (prev, chunk) => {
        await prev;
        await Promise.all(
          chunk.map(async ({ name, version }) => {
            const vulns = await queryOsvForPackage(name, version);
            const key = cacheKey(name, version);
            results.set(key, vulns);
          })
        );
      },
      Promise.resolve()
    );

    const diagnosticsByFile = checkItems.reduce<
      Map<string, vscode.Diagnostic[]>
    >((acc, item) => {
      const key = cacheKey(item.name, item.version);
      const vulns = results.get(key);
      if (!vulns || vulns.length === 0) {
        return acc;
      }

      const first = vulns[0];
      const count = vulns.length;

      const messageParts: string[] = [
        `${item.name}@${item.version} has ${count} known vulnerability${
          count > 1 ? 'ies' : 'y'
        } in OSV.dev.`
      ];
      if (!item.isDirect) {
        messageParts.push('(transitive dependency)');
      }
      if (first.summary) {
        messageParts.push(`Example: ${first.summary}`);
      }
      if (first.id) {
        messageParts.push(`(e.g. ${first.id})`);
      }

      const diagnostic = new vscode.Diagnostic(
        item.range,
        messageParts.join(' '),
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

      const fileKey = item.uri.toString();
      const list = acc.get(fileKey) ?? [];
      acc.set(fileKey, [...list, diagnostic]);
      return acc;
    }, new Map());

    Array.from(diagnosticsByFile.entries()).forEach(([uriStr, diags]) => {
      diagnostics.set(vscode.Uri.parse(uriStr), diags);
    });

    const allDiagnostics = Array.from(diagnosticsByFile.values()).flat();
    const transitiveIssueCount = allDiagnostics.filter((d) =>
      d.message.includes('(transitive dependency)')
    ).length;
    const directIssueCount = allDiagnostics.length - transitiveIssueCount;

    if (allDiagnostics.length === 0) {
      vscode.window.showInformationMessage(
        'Cerbe: No known vulnerabilities found for listed dependencies (according to OSV.dev).'
      );
      updateStatusBar(
        '$(shield) Cerbe 0 issues',
        'No known vulnerabilities found for listed dependencies'
      );
    } else {
      vscode.window.showWarningMessage(
        `Cerbe: Found ${allDiagnostics.length} vulnerable dependency entries across ${pkgUris.length} package.json file(s).`
      );
      updateStatusBar(
        `$(shield) Cerbe ${allDiagnostics.length} issue${
          allDiagnostics.length === 1 ? '' : 's'
        }`,
        `Direct issues: ${directIssueCount}, transitive issues: ${transitiveIssueCount}`
      );
    }
  } catch (err: any) {
    console.error('Error scanning dependencies', err);
    vscode.window.showErrorMessage(
      `Cerbe: Failed to scan dependencies: ${err?.message ?? String(err)}`
    );
    updateStatusBar(
      '$(error) Cerbe Error',
      'Click to retry scanning dependencies'
    );
  }
};

// ---- Lockfile helpers (transitive deps) ----

/**
 * Reads any available lockfile (npm, yarn, pnpm) and flattens all dependencies
 * (including transitive) into a map of name -> version.
 */
const readLockfileDependencies = async (): Promise<
  Map<string, string> | undefined
> => {
  const acc = new Map<string, string>();

  await Promise.all([
    readNpmLockInto(acc),
    readYarnLockInto(acc),
    readPnpmLockInto(acc)
  ]);

  return acc.size ? acc : undefined;
};

// npm: package-lock.json (anywhere in workspace)
const readNpmLockInto = async (acc: Map<string, string>): Promise<void> => {
  const lockUris = await vscode.workspace.findFiles(
    '**/package-lock.json',
    '**/node_modules/**'
  );
  if (!lockUris.length) {
    return;
  }

  await Promise.all(
    lockUris.map(async (lockUri) => {
      try {
        const doc = await vscode.workspace.openTextDocument(lockUri);
        const lockJson = JSON.parse(doc.getText()) as any;

        if (lockJson.dependencies && typeof lockJson.dependencies === 'object') {
          collectDepsFromNpmLock(lockJson.dependencies, acc);
        }
      } catch (err) {
        console.warn('Failed to read package-lock.json:', err);
      }
    })
  );
};

const collectDepsFromNpmLock = (
  deps: Record<string, any>,
  acc: Map<string, string>
) => {
  Object.entries(deps).forEach(([name, info]) => {
    if (!info || typeof info !== 'object') {
      return;
    }

    const version =
      typeof (info as any).version === 'string'
        ? (info as any).version
        : undefined;
    if (version && !acc.has(name)) {
      acc.set(name, version);
    }

    if (
      (info as any).dependencies &&
      typeof (info as any).dependencies === 'object'
    ) {
      collectDepsFromNpmLock(
        (info as any).dependencies as Record<string, any>,
        acc
      );
    }
  });
};

// yarn: yarn.lock (classic, anywhere in workspace)
const readYarnLockInto = async (acc: Map<string, string>): Promise<void> => {
  const yarnUris = await vscode.workspace.findFiles(
    '**/yarn.lock',
    '**/node_modules/**'
  );
  if (!yarnUris.length) {
    return;
  }

  await Promise.all(
    yarnUris.map(async (yarnUri) => {
      try {
        const doc = await vscode.workspace.openTextDocument(yarnUri);
        parseYarnLock(doc.getText(), acc);
      } catch (err) {
        console.warn('Failed to read yarn.lock:', err);
      }
    })
  );
};

/**
 * Very lightweight yarn.lock parser (v1-style).
 * Extracts name + version from stanzas like:
 *
 * "pkg-name@^1.0.0":
 *   version "1.2.3"
 */
const parseYarnLock = (text: string, acc: Map<string, string>) => {
  const lines = text.split(/\r?\n/);
  let currentNames: string[] = [];
  let currentVersion: string | undefined;

  const flush = () => {
    if (!currentVersion) {
      return;
    }
    const version = currentVersion;
    currentNames.forEach((spec) => {
      const name = extractNameFromYarnSpec(spec);
      if (!name || acc.has(name)) {
        return;
      }
      acc.set(name, version);
    });
    currentNames = [];
    currentVersion = undefined;
  };

  lines.forEach((rawLine) => {
    const line = rawLine.trimEnd();

    if (line.endsWith(':') && !line.startsWith('  ') && line !== 'resolution:') {
      flush();
      const keyPart = line.slice(0, -1).trim();
      currentNames = keyPart.split(/,\s*/).map((s) => s.replace(/^"|"$/g, ''));
      return;
    }

    if (line.startsWith('version ')) {
      const match = line.match(/version\s+"([^"]+)"/);
      currentVersion = match ? match[1] : currentVersion;
      return;
    }

    if (!line.startsWith(' ') && line.trim() === '') {
      flush();
    }
  });

  flush();
};

const extractNameFromYarnSpec = (spec: string): string | undefined => {
  if (!spec) {
    return undefined;
  }

  if (spec.startsWith('@')) {
    const secondAt = spec.indexOf('@', 1);
    return secondAt === -1 ? spec : spec.slice(0, secondAt);
  }

  const atIndex = spec.indexOf('@');
  return atIndex === -1 ? spec : spec.slice(0, atIndex);
};

// pnpm: pnpm-lock.yaml (anywhere in workspace)
const readPnpmLockInto = async (acc: Map<string, string>): Promise<void> => {
  const pnpmUris = await vscode.workspace.findFiles(
    '**/pnpm-lock.yaml',
    '**/node_modules/**'
  );
  if (!pnpmUris.length) {
    return;
  }

  await Promise.all(
    pnpmUris.map(async (pnpmUri) => {
      try {
        const doc = await vscode.workspace.openTextDocument(pnpmUri);
        parsePnpmLock(doc.getText(), acc);
      } catch (err) {
        console.warn('Failed to read pnpm-lock.yaml:', err);
      }
    })
  );
};

/**
 * Very lightweight pnpm-lock.yaml parser.
 * We look for lines under "packages:" that look like:
 *
 *   /name/1.2.3:
 *   /@scope/name/4.5.6:
 *
 * and extract name + version from the path.
 */
const parsePnpmLock = (text: string, acc: Map<string, string>) => {
  const lines = text.split(/\r?\n/);
  let inPackagesSection = false;

  lines.forEach((rawLine) => {
    const line = rawLine.replace(/\t/g, '  ');

    if (!inPackagesSection) {
      if (line.trim() === 'packages:') {
        inPackagesSection = true;
      }
      return;
    }

    if (!line.startsWith('  ') && line.trim().length > 0) {
      inPackagesSection = false;
      return;
    }

    const match = line.match(/^\s{2}\/(.+?)\/([^/:\s]+):\s*$/);
    if (!match) {
      return;
    }

    const fullName = match[1];
    const version = match[2];

    if (!acc.has(fullName)) {
      acc.set(fullName, version);
    }
  });
};

// ---- OSV API + cache helpers ----

const cacheKey = (name: string, version: string): string =>
  `${name}@${version}`;

/**
 * Query OSV.dev for a specific npm package version, with background caching.
 */
const queryOsvForPackage = async (
  name: string,
  version: string
): Promise<OsvVulnerability[] | undefined> => {
  const key = cacheKey(name, version);
  const now = Date.now();

  const cached = vulnCache.get(key);
  if (cached && now - cached.fetchedAt < VULN_CACHE_TTL_MS) {
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
    return cached?.vulns;
  }
};

// ---- Utility functions ----

/**
 * Best-effort normalization:
 *  - strips leading ^ or ~
 *  - returns undefined for non-semver-ish values (git urls, file: etc.)
 */
const normalizeVersion = (raw: string): string | undefined => {
  const trimmed = raw.trim();

  if (
    trimmed.startsWith('git+') ||
    trimmed.startsWith('file:') ||
    trimmed.startsWith('http://') ||
    trimmed.startsWith('https://') ||
    trimmed === 'latest'
  ) {
    return undefined;
  }

  const stripped = trimmed.replace(/^[~^]/, '');

  if (!/\d+\.\d+/.test(stripped)) {
    return undefined;
  }

  return stripped;
};

/**
 * Finds the range in package.json covering `"name": "version"` for diagnostics.
 * If not found, falls back to the first line of the file.
 */
const findDependencyRangeInPackageJson = (
  doc: vscode.TextDocument,
  depName: string
): vscode.Range => {
  const text = doc.getText();
  const regex = new RegExp(
    `"${escapeRegex(depName)}"\\s*:\\s*"(.*?)"`,
    'g'
  );
  const match = regex.exec(text);
  if (!match) {
    const firstLine = doc.lineAt(0);
    return firstLine.range;
  }

  const startOffset = match.index;
  const endOffset = match.index + match[0].length;

  const startPos = doc.positionAt(startOffset);
  const endPos = doc.positionAt(endOffset);
  return new vscode.Range(startPos, endPos);
};

const escapeRegex = (value: string): string =>
  value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const updateStatusBar = (text: string, tooltip: string) => {
  if (!statusBarItem) {
    return;
  }
  statusBarItem.text = text;
  statusBarItem.tooltip = tooltip;
  statusBarItem.show();
};

const safeParsePackageJson = (
  doc: vscode.TextDocument
): PackageJson | undefined => {
  try {
    return JSON.parse(doc.getText()) as PackageJson;
  } catch (err: any) {
    vscode.window.showWarningMessage(
      `Cerbe: Skipping invalid package.json at ${doc.uri.fsPath}: ${err?.message ?? String(err)}`
    );
    return undefined;
  }
};
