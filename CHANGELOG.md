# Changelog

All notable changes to `secure-lock-cli` will be documented in this file.

## 1.2.0 - 2026-06-01

### Added

- **yarn** support — reads `yarn.lock` classic v1 (custom format) and berry v2+ (YAML). dev flags are inferred from a sibling `package.json`. Auto-detection priority is now pnpm > bun > yarn > npm, with an explicit `--yarn` flag.
- **`--fix`** — prints, per package manager, the upgrade command for each currently-vulnerable package. The target is the smallest version above the installed one that escapes *every* vulnerable range (from advisory patched versions + latest), so the bump is minimal and verified. Packages with no safe target are skipped. In `--json` mode each package gains a `fix` object.

### Install / upgrade

```bash
composer global require jeffersongoncalves/secure-lock-cli

```
## 1.1.0 - 2026-06-01

### Added

- **pnpm** support — reads `pnpm-lock.yaml` (lockfileVersion 5/6/9), including scoped packages and peer-dependency suffixes.
- **bun** support — reads the `bun.lock` text lockfile (JSONC). The binary `bun.lockb` is rejected with a hint to generate the text lockfile.
- The `ECO` column (and a new JSON `manager` field) now show the real package manager a dependency came from: `composer`, `npm`, `pnpm` or `bun`.
- Explicit `--pnpm` and `--bun` path flags, mirroring `--npm`. JS lockfiles are auto-detected in the project directory by priority (pnpm > bun > npm).

All JavaScript managers resolve against the shared npm ecosystem, so advisory and registry lookups are unchanged.

### Install / upgrade

```bash
composer global require jeffersongoncalves/secure-lock-cli


```
## 1.0.2 - 2026-06-01

### Fixed

- `secure-lock --version` reported the wrong version after install. The release pipeline now treats `version.txt` as the single source of truth for the embedded version and creates the tag on a commit whose committed PHAR already embeds the correct version — removing the git-describe / tag-move / Packagist dist-cache race that shipped 1.0.0/1.0.1 binaries reporting a stale version.

No changes to the audit behavior.

### Install / upgrade

```bash
composer global require jeffersongoncalves/secure-lock-cli



```
## 1.0.1 - 2026-06-01

### Fixed

- `composer global require` failed to resolve on setups with newer global Laravel components. The prebuilt PHAR bundles its runtime libraries, so `illuminate/http`, `composer/semver` and `guzzlehttp/guzzle` moved from `require` to `require-dev` — installing the CLI now only needs PHP `^8.2` and no longer forces consumers to resolve Laravel 12 packages.

No functional changes to the audit itself.

### Install

```bash
composer global require jeffersongoncalves/secure-lock-cli




```
## 1.0.0 - 2026-06-01

Initial release.

secure-lock audits Composer (composer.lock) and npm (package-lock.json v1/v2/v3) dependencies for known vulnerabilities and tells whether an available update actually leaves the vulnerable range — distinguishing a useful fix from a useless bump.

### Highlights

- `audit` command (default): risk-sorted table, per-verdict summary, `--json`, `--only-vuln`, `--no-dev`, `--cache-ttl`, `--github-token`.
- Verdicts: VULN / SAFE_UPDATE / RISKY_UPDATE / UPDATE / OK.
- CI exit codes: 0 clean, 1 on VULN/RISKY_UPDATE, 2 on input error.
- GitHub Advisory Database + Packagist/npm registries, composer/semver (GHSA AND-ranges), file-backed HTTP cache.
- `self-update` for PHAR installs.

### Install

```bash
composer global require jeffersongoncalves/secure-lock-cli





```