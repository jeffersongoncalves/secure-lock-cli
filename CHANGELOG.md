# Changelog

All notable changes to this project will be documented in this file.

## [1.7.4] - 2026-09-08

### Bug Fixes

- **deps:** Update guzzlehttp/guzzle to patch security advisories
- **ci:** Publish release as draft until PHAR asset is attached
- **ci:** Use the correct resolve-version output in the publish step

### CI/CD

- Pin actions to commit SHA, add dependabot cooldown/composer, trim dist archive
- **release:** Generate CHANGELOG.md and release notes with git-cliff

### Documentation

- Add Buy Me a Coffee sponsor link
- Standardize README section structure

### Miscellaneous Tasks

- Bump guzzlehttp/guzzle and guzzlehttp/psr7 for security advisories
- Add GitHub Sponsors to FUNDING.yml

## [1.7.3] - 2026-07-24

### CI/CD

- Replace split build/changelog/publish-phar workflows with a single release job

### Refactor

- Use jeffersongoncalves/laravel-zero-self-update package

## [1.7.2] - 2026-06-06

### CI/CD

- **build:** Serialize builds with a concurrency group to avoid ref-lock race

### Miscellaneous Tasks

- Bump version to 1.7.2

## [1.7.1] - 2026-06-01

### Other

- Chunk advisory fallback requests to bound failure blast radius

On a large project (hundreds of npm packages) the single npm-audit bulk POST
could fail as a whole — e.g. throttled after the big lookup burst — leaving
every JS package UNKNOWN while Composer (a different host) recovered. The npm
and Packagist fallbacks now split into batches of 80: one bad batch no longer
fails the rest, and each request stays small, so it is far less likely to hit
a size/rate threshold. For large projects, setting GITHUB_TOKEN avoids the
rate-limited fallback path entirely.

Bumps version.txt to 1.7.1.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [1.7.0] - 2026-06-01

### Other

- Add npm audit advisory fallback for the JS ecosystem

Mirrors the Packagist fallback: when an npm/pnpm/bun/yarn package's GitHub
lookup fails, the npm registry audit bulk endpoint is queried as a redundant
source. The installed and latest versions are posted per package (the bulk
endpoint filters by version), so Advisory::affects() recomputes current/latest
alike. HttpFetcher gains a cache-aware post(). Every ecosystem can now be
audited with no GITHUB_TOKEN. Disable with --no-npm-audit.

Bumps version.txt to 1.7.0.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [1.6.0] - 2026-06-01

### Other

- Make --fix transitive-aware (overrides / resolutions)

Packages now carry isDirect, set by every lock reader (npm root deps, npm v1
depth, pnpm/bun/yarn direct sets). The Fixer uses it: a direct dependency
gets a plain add/require/install, while a transitive one — which an install
cannot reach — is pinned via the manager's override mechanism: overrides
(npm/bun), pnpm.overrides (pnpm) or resolutions (yarn). Composer keeps
composer require, which pins transitive packages too. The JSON fix object
gains a transitive flag.

Bumps version.txt to 1.6.0.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [1.5.0] - 2026-06-01

### Other

- Add Packagist Security Advisories as a redundant backend for Composer

When a Composer package's GitHub advisory lookup fails (most often the rate
limit without a token), the Packagist Security Advisories API is queried as a
fallback — one batched packages[] request for every failed package — and the
result is recovered instead of being left UNKNOWN. Composer can now be audited
with no GITHUB_TOKEN at all. npm has no Packagist equivalent, so it is
unaffected. Disable with --no-packagist.

affectedVersions is parsed as a composer constraint where '|' is OR (each
alternative a vulnerable range). The Auditor was split into enrich → Packagist
recovery → classify so the fallback slots in cleanly.

Bumps version.txt to 1.5.0.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [1.4.0] - 2026-06-01

### Other

- Concurrent lookups via Http::pool and PHPStan level 6 in CI

#3 Registry and advisory lookups for every package are now fired concurrently
through a shared HttpFetcher (Http::pool, capped), collapsing the audit's many
sequential round-trips into a few waves. The fetcher centralises cache reuse
and the failure/rate-limit semantics; clients expose url()/parse() so the
Auditor can batch the first wave and only paginate the rare >100-advisory
package sequentially.

#8 Adds larastan/PHPStan at level 6 (clean, no baseline), a phpstan.yml
workflow, and wires it into 'composer test' (lint + types + unit).

Bumps version.txt to 1.4.0.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- Avoid dead-catch in self-update by calling throwing methods directly

components->task() swallows the closure's exception, so the surrounding
catch was unreachable (PHPStan flagged it on PHP 8.2). Call download() and
replacePhar() directly inside the try so their RuntimeException propagates
to the handler.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [1.3.0] - 2026-06-01

### Other

- Add unverified-lookup detection, advisory ignore list, and SARIF output

#1 Failed advisory lookups (rate limit, network error) are no longer mistaken
for 'no advisories'. AdvisoryClient returns an AdvisoryResult that flags
failure, classified as a new UNKNOWN verdict (never OK/SAFE). Failures are not
cached, advisory pagination is followed, and --fail-on-unverified makes CI fail
when anything could not be checked.

#4 --ignore=<GHSA|CVE> (repeatable) plus a secure-lock.json config suppress
accepted or un-patchable advisories; entries may carry an expiry after which
they re-surface.

#6 --sarif emits SARIF 2.1.0 for GitHub code scanning (Security tab), one rule
and result per currently-vulnerable package with severity-mapped levels.

Bumps version.txt to 1.3.0.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [1.2.1] - 2026-06-01

### Other

- Make all CLI output English; add audit and --fix screenshots

Verdict badges/labels, table headers (STATUS/ECO/PACKAGE/CURRENT/LATEST/NOTE),
the summary line and the fix section are now English for an international
audience. Adds two terminal screenshots (real tool output) to the README
demonstrating the audit table and the --fix minimal-safe-version suggestions.

Bumps version.txt to 1.2.1.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [1.2.0] - 2026-06-01

### Other

- Add yarn lockfile support and the --fix flag

LockReader::readYarn parses classic v1 yarn.lock (custom format, multi-
descriptor blocks) and berry v2+ (YAML, npm: descriptors); dev flags are
inferred from a sibling package.json. yarn joins the npm-ecosystem managers
with label 'yarn' and is auto-detected (pnpm > bun > yarn > npm) plus an
explicit --yarn flag.

--fix prints, per manager, the upgrade command for each currently-vulnerable
package: the smallest version above the installed one that escapes every
vulnerable range (from advisory patched versions + latest), or skips packages
with no safe target. JSON mode gains a per-package 'fix' object.

Bumps version.txt to 1.2.0.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [1.1.0] - 2026-06-01

### Other

- Add pnpm and bun lockfile support; show real manager in ECO column

LockReader gains readPnpm (pnpm-lock.yaml v5/v6/v9, via symfony/yaml) and
readBun (bun.lock text JSONC; bun.lockb binary is rejected with a hint). Both
resolve to the npm ecosystem for registry and advisory lookups, so
RegistryClient/AdvisoryClient are unchanged.

Package now carries a display-only manager label (composer/npm/pnpm/bun)
surfaced in the ECO column and the JSON 'manager' field. The audit command
auto-detects a single JS lockfile by priority (pnpm > bun > npm) and adds
explicit --pnpm/--bun flags mirroring --npm.

Bumps version.txt to 1.1.0.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [1.0.2] - 2026-06-01

### Other

- Make version.txt the source of truth for the embedded build version

Eliminates the Packagist dist-cache race: build.yml and publish-phar now read
the version from version.txt instead of resolving a git tag, and the move-tag
dance is removed. The release tag is created on a commit whose committed
builds/secure-lock already embeds the correct version, so the dist Packagist
serves is right from the first read — no force-moved tag to miss.

Bumps version.txt to 1.0.2 for the next release.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [1.0.1] - 2026-06-01

### Other

- Move runtime libs to require-dev so the PHAR install only needs PHP

illuminate/http, composer/semver and guzzle are bundled inside the prebuilt
PHAR, so they must not be hard runtime requires — otherwise composer global
require forces consumers to resolve Laravel 12 components, which conflicts
with a global Laravel 13 install. Mirrors the git-worktree-cli layout where
require is just php and everything else is dev (bundled at build time).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [1.0.0] - 2026-06-01

### Other

- Initial release: secure-lock dependency audit CLI

Laravel Zero CLI auditing Composer (composer.lock) and npm
(package-lock.json v1/v2/v3) dependencies. For each package: resolves the
latest stable version (Packagist/npm), fetches GitHub Advisory Database
advisories, and classifies into VULN / SAFE_UPDATE / RISKY_UPDATE / UPDATE
/ OK, distinguishing a bump that leaves the vulnerable range from one that
stays exposed.

- audit command (default): risk-sorted table, per-verdict summary, --json,
  --only-vuln, --no-dev, --cache-ttl, --github-token; CI exit codes 0/1/2
- composer/semver for comparisons and GHSA AND-ranges
- file-backed HTTP cache; Http facade with retry/timeout
- self-update for PHAR installs
- 23 Pest tests (Http::fake), Pint, GitHub Actions (tests/build/publish/changelog)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- Reset CHANGELOG to stub (maintained by update-changelog.yml on release)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- Add portfolio banner to README

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
- Fix parallel test race on shared lockfile basename

writeTempLock now writes each fixture to a unique tests/tmp subdir, so the
parallel runner no longer races two tests writing the same composer.lock.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>


