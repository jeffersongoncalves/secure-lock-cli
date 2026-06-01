# Changelog

All notable changes to `secure-lock-cli` will be documented in this file.

## 1.0.0 - 2026-05-31

Initial release. CLI to audit Composer (`composer.lock`) and npm
(`package-lock.json`) dependencies for known vulnerabilities and to
distinguish a useful update that leaves the vulnerable range from a
useless bump that stays exposed.

### What's included

- **`audit`** (default command) — reads both lockfiles, queries Packagist /
  npm for the latest stable version and the GitHub Advisory Database for
  known advisories, then classifies each package into one of five verdicts:
  `VULN`, `SAFE_UPDATE`, `RISKY_UPDATE`, `UPDATE`, `OK`.
- Human-readable table sorted by risk, a per-verdict summary, and a
  `--json` mode for CI.
- CI-friendly exit codes: `0` clean, `1` when a `VULN`/`RISKY_UPDATE` is
  present, `2` on input errors.
- File-backed HTTP cache with a configurable `--cache-ttl`.
- **`self-update`** for PHAR installs.
