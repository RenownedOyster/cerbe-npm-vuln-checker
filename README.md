![Cerberus logo](images/coverImage.png)

# Cerbe: NPM Vulnerability Checker

A VS Code extension that scans your workspace dependencies (direct and transitive) using [OSV.dev](https://osv.dev) and highlights packages with known vulnerabilities.

## Features

- Automatically scans when:
  - A workspace with a `package.json` is opened
  - `package.json`, `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml` changes
- Looks at:
  - Direct dependencies in `dependencies` and `devDependencies` from the root `package.json`
  - Transitive dependencies from:
    - `package-lock.json` (npm)
    - `yarn.lock` (Yarn)
    - `pnpm-lock.yaml` (pnpm)
- Uses the OSV.dev public API to check each `name@version` for known vulnerabilities.
- Adds diagnostics for vulnerable packages (squiggles in `package.json` + entries in the Problems panel).
  - Direct dependencies are highlighted on their own lines.
  - Transitive dependencies are marked with `(transitive dependency)` and attached to the first line of `package.json`.
- Each diagnostic links to the corresponding OSV vulnerability page (clickable in the Problems panel).
- Status bar integration:
  - Shows scan progress (`Scanning…`)
  - Shows number of detected issues (`N issues`)
  - Clickable to trigger a rescan.
- Background caching of OSV results per `name@version` to avoid redundant network calls.
- Parallel OSV queries (batched) for faster scans on larger projects.

> Note:
>
> - Only npm ecosystem packages are checked (what OSV labels as `ecosystem: "npm"`).
> - Version parsing is best-effort and focuses on typical semver ranges.
> - This tool can tell you what is _known_ to be vulnerable according to OSV; it does **not** guarantee that packages without records are safe.

## Usage

Most of the time you don’t need to do anything: the extension scans automatically.

1. Open a folder that contains a `package.json` in the root.
2. The extension will scan automatically and:
   - Show status in the status bar (`Cerbe:…`).
   - Populate diagnostics in `package.json` and the Problems panel.
3. To manually trigger a scan:
   - Open the Command Palette (Ctrl+Shift+P / Cmd+Shift+P).
   - Run: **Cerbe NPM Vulnerability checker: Scan package.json**.
   - Or click the status bar item **“Cerbe:…”**.

Then:

- Look for warnings (squiggles) in `package.json`.
- Open the Problems panel to see all vulnerable dependencies.
- Click the diagnostic code to open the OSV entry in your browser.

## Privacy

The extension sends only:

- package name (e.g. `lodash`)
- normalized version (e.g. `4.17.21`)

to the OSV.dev API at:

- `https://api.osv.dev/v1/query`

No source code or file paths are sent.

## License

MIT
