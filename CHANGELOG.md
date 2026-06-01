# Changelog

All notable changes to `secure-lock-cli` will be documented in this file.

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