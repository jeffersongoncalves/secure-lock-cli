# Changelog

All notable changes to `secure-lock-cli` will be documented in this file.

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