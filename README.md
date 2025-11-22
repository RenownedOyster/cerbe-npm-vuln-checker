![Cerberus logo](images/coverImage.png)

# Cerbe — NPM Vulnerability Checker

![Version](https://img.shields.io/visual-studio-marketplace/v/RenownedOyster.cerbe-npm-vuln-checker)
![Installs](https://img.shields.io/visual-studio-marketplace/i/RenownedOyster.cerbe-npm-vuln-checker)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Cerbe is a VS Code extension that scans your workspace dependencies — direct and transitive — using the [OSV.dev](https://osv.dev) security database. Vulnerable packages are highlighted directly inside your `package.json` files and surfaced in a dedicated sidebar view, giving you instant visibility into supply-chain risk.

Cerbe is monorepo-aware, performs parallel OSV queries, and uses background caching for fast rescans.

---

## ✨ Features

Cerbe automatically detects vulnerable dependencies across your entire workspace.

### Dependency scanning

- Scans **every** `package.json` in your workspace (monorepo-friendly)
- Checks:
  - `dependencies`
  - `devDependencies` (configurable)
- Transitive dependencies are discovered via:
  - `package-lock.json` (npm)
  - `yarn.lock` (Yarn)
  - `pnpm-lock.yaml` (pnpm)

### Severity-aware analysis

- Uses OSV `severity` (CVSS) information when available
- Computes a **max severity** per package and per file
- Shows severity level in:
  - Diagnostics messages
  - TreeView labels and tooltips
- Visual severity prefixes:
  - 🛑 Critical
  - 🔴 High
  - 🟠 Medium
  - 🟡 Low
  - ⚪️ Unknown

### Sidebar TreeView (“Cerbe Vulnerabilities”)

Accessible from the Explorer view as **Cerbe Vulnerabilities**:

- **Level 1: Files**
  - One node per `package.json` with issues
  - Label includes relative path, issue count, and severity emoji
- **Level 2: Packages**
  - One node per vulnerable `package@version`
  - Shows:
    - Severity level
    - Number of vulnerabilities
    - Direct vs transitive
    - For transitive deps, a “via …” chain (e.g. `via react > scheduler`)
- **Level 3: Vulnerabilities**
  - One node per OSV vulnerability ID
  - Shows summary and severity
  - Clicking opens the OSV vulnerability page in your browser

Each package node lets you jump straight into the relevant `package.json` selection.

### Monorepo-aware lockfile mapping

- Lockfiles are associated with the **nearest** `package.json` up the directory tree
- Transitive vulnerabilities discovered in lockfiles are attached to the correct project/package, even in large monorepos
- Works across:
  - Multiple apps/packages
  - Multiple lockfiles per workspace

### Status bar integration

- Shows current status:
  - Ready
  - Scanning…
  - Issue counts
- Clickable to trigger a **manual rescan**

### Smarter scanning behaviour

- Automatic scanning is configurable:
  - On workspace open
  - On file changes
  - Or manual only
- Debounced scanning to avoid thrashing during installs or large edits
- Parallel OSV queries with configurable concurrency
- Background caching per `name@version` to avoid redundant network calls

> **Notes**
>
> - Only NPM-ecosystem packages are checked (`ecosystem: "npm"`).
> - Version parsing is best-effort (focus on typical semver).
> - OSV.dev reports _known_ vulnerabilities — absence of a report does **not** guarantee safety.

---

## ⚙️ Configuration

All settings are under `cerbe` in the VS Code settings UI or `settings.json`.

- `cerbe.autoScan`

  - When Cerbe should automatically scan.
  - Values:
    - `"all"` – scan on workspace open and relevant file changes (default)
    - `"onSave"` – reserved for future use (currently behaves like `"all"` for file changes)
    - `"manual"` – only scan when you explicitly run the command or click the status bar item

- `cerbe.scanTransitive`

  - `true` / `false` (default: `true`)
  - Enable or disable scanning of transitive dependencies via lockfiles.

- `cerbe.maxConcurrency`

  - Number (default: `10`)
  - Maximum number of parallel OSV queries to run at once.

- `cerbe.includeDevDependencies`

  - `true` / `false` (default: `true`)
  - Whether to include `devDependencies` when scanning.

- `cerbe.excludeGlobs`
  - Array of glob patterns (default: `[]`)
  - Additional paths to exclude from scanning.
  - `node_modules` is always excluded automatically; use this to ignore things like `**/examples/**` or `**/fixtures/**`.

---

## 🚀 Usage

Most of the time, Cerbe works automatically with zero setup.

1. Open a folder containing one or more `package.json` files.
2. Cerbe scans automatically (depending on `cerbe.autoScan`) and:

   - Updates the status bar with scan status and issue counts
   - Adds diagnostics (squiggles) in each affected `package.json`
   - Populates the **Problems** panel with all detected vulnerabilities
   - Populates the **Cerbe Vulnerabilities** sidebar tree

3. To manually trigger a scan:

   - Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
   - Run: **Cerbe: Scan Dependencies**
   - Or click the Cerbe status bar item

4. To explore results visually:
   - Open the **Explorer** view
   - Find the **Cerbe Vulnerabilities** section
   - Expand:
     - File → Package → Vulnerability
     - Click a package to jump into `package.json`
     - Click a vulnerability node to open the OSV entry in your browser

---

## 🔒 Privacy

Cerbe sends **only**:

- Package name (e.g. `lodash`)
- Normalized version (e.g. `4.17.21`)

To the OSV.dev API:

- `https://api.osv.dev/v1/query`

No source code, file contents, or file paths are sent. The extension does not transmit any project metadata beyond the package name and version being checked.

---

## 📝 License

This extension is licensed under the **MIT License**.  
See the included `LICENSE` file for details.
