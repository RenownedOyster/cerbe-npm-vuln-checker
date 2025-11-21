![Cerberus logo](images/coverImage.png)

# Cerbe — NPM Vulnerability Checker

![Version](https://img.shields.io/visual-studio-marketplace/v/RenownedOyster.cerbe)
![Installs](https://img.shields.io/visual-studio-marketplace/i/RenownedOyster.cerbe)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Cerbe is a VS Code extension that scans your workspace dependencies—direct and transitive—using the OSV.dev security database. Vulnerable packages are highlighted directly inside your `package.json` files, making supply-chain risks visible instantly.

Cerbe is monorepo-friendly, performs parallel OSV queries, and uses background caching for fast rescans.

---

## ✨ Features

Cerbe automatically detects vulnerable dependencies across your entire workspace.

- **Automatic scanning when:**

  - Opening a workspace with one or more `package.json` files
  - Editing or saving:
    - `package.json`
    - `package-lock.json`
    - `yarn.lock`
    - `pnpm-lock.yaml`

- **Direct dependency scanning**

  Looks at:

  - `dependencies`
  - `devDependencies`
  - In _every_ `package.json` (monorepo-friendly)

- **Transitive dependency scanning** from lockfiles:

  - npm: `package-lock.json`
  - Yarn: `yarn.lock`
  - pnpm: `pnpm-lock.yaml`

- **OSV.dev API integration**

  Each `name@version` is checked against the OSV vulnerability database.

- **Inline diagnostics**

  - Vulnerable direct dependencies show squiggles on their lines
  - Transitive vulnerabilities attach to the top of the corresponding `package.json`
  - Each vulnerability includes a direct link to the OSV entry

- **Status bar integration**

  - Shows scan progress (`Scanning…`)
  - Displays total issue count
  - Clickable to trigger a manual rescan

- **Performance features**

  - Background caching per `name@version`
  - Parallel OSV requests (batched)
  - Efficient lockfile parsing
  - Minimal noise, fast updates

> **Notes**
>
> - Only NPM-ecosystem packages are checked (`ecosystem: "npm"`).
> - Version parsing is best-effort.
> - OSV.dev reports _known_ vulnerabilities—absence of a report does **not** guarantee safety.

---

## 🚀 Usage

Most of the time, Cerbe works automatically with zero setup.

1. Open any folder containing one or more `package.json` files.
2. Cerbe scans automatically and:

   - Updates the status bar (`Cerbe: …`)
   - Adds warnings (squiggles) in each affected `package.json`
   - Populates results in the **Problems** panel

3. To manually trigger a scan:

   - Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
   - Run: **Cerbe: Scan Dependencies**
   - Or click the Cerbe status bar item

Then:

- Check for warnings in your `package.json`
- Open the Problems panel to see a full list of vulnerabilities
- Click any diagnostic code to open the OSV vulnerability page

---

## 🔒 Privacy

Cerbe sends **only**:

- Package name (e.g., `lodash`)
- Normalized version (e.g., `4.17.21`)

To OSV.dev:

https://api.osv.dev/v1/query

No file contents, paths, or project metadata are transmitted.

---

## 📝 License

This extension is licensed under the **MIT License**.  
See the included `LICENSE` file for details.
