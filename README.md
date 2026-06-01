# secure-lock-cli

`secure-lock` audits a project's dependencies and answers three questions
for every package:

1. **Is there a newer version?** (registry lookup)
2. **Is the installed version vulnerable?** (advisory database lookup)
3. **Is the available update actually safe?** — i.e. does the target version
   really leave the vulnerable range, instead of merely being newer?

Born out of the recent wave of supply-chain attacks (compromised /
vulnerable packages on Composer and npm), the tool distinguishes a *useful
bump that fixes the flaw* from a *useless bump that stays exposed*. It
covers two ecosystems: **Composer** (`composer.lock`) and **npm**
(`package-lock.json`, v1/v2/v3).

Built with [Laravel Zero](https://laravel-zero.com) and modeled on the
other CLIs in this monorepo.

## Requirements

- PHP `^8.2`
- A `composer.lock` and/or a `package-lock.json` to audit
- Optionally a `GITHUB_TOKEN` (raises the GitHub Advisory API rate limit
  from ~60 req/h to 5000 req/h)

## Install

### Global (recommended)

```bash
composer global require jeffersongoncalves/secure-lock-cli
```

The binary `secure-lock` will be on your `PATH` as long as Composer's
global `vendor/bin` is in it.

### From source

```bash
git clone https://github.com/jeffersongoncalves/secure-lock-cli.git
cd secure-lock-cli
composer install
```

## Usage

```bash
secure-lock                      # audit the current project (default command)
secure-lock --only-vuln          # only show packages at risk
secure-lock --no-dev             # ignore dev dependencies
secure-lock --json > audit.json  # structured output for CI
secure-lock --dir=/path/to/proj  # audit a specific directory
```

### Options

```
--dir=            Project directory (defaults to the current directory)
--composer=       Explicit path to composer.lock
--npm=            Explicit path to package-lock.json
--only-vuln       Show only packages at risk
--no-dev          Ignore development dependencies
--json            Structured JSON output (for CI)
--github-token=   GitHub token (or the GITHUB_TOKEN env var)
--cache-ttl=3600  HTTP cache TTL in seconds (0 disables caching)
```

## Verdicts

For each package the tool compares the advisories that hit the **current**
version against those still hitting the **latest** version:

| Verdict | Badge | Meaning |
|---------|-------|---------|
| `VULN` | `● VULN` (red) | vulnerable now, no published fix |
| `SAFE_UPDATE` | `● SEGURO` (green) | the update **fixes** the vulnerability |
| `RISKY_UPDATE` | `● RISCO` (magenta) | an update exists but stays exposed |
| `UPDATE` | `● UPDATE` (cyan) | newer version, no known vulnerability |
| `OK` | `● OK` (gray) | up to date and clean |

The table is sorted by risk (`VULN` > `RISCO` > `SEGURO` > `UPDATE` > `OK`)
and the `OBSERVAÇÃO` column shows the highest-severity advisory as
`SEVERITY CVE-XXXX (+N)` (the CVE when present, otherwise the GHSA id).

## Exit codes (for CI)

- `0` — no critical risk.
- `1` — a `VULN` or `RISKY_UPDATE` was found (fails the pipeline).
- `2` — input error (lockfile not found, invalid JSON, etc.).

### GitHub Actions

```yaml
- run: secure-lock --no-dev
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## How it works

- **Registry** — Composer: `repo.packagist.org/p2/{name}.json`, walking every
  version and ignoring pre-releases (`alpha|beta|rc|dev|next|canary|nightly`)
  to find the highest stable. npm: `registry.npmjs.org/{name}` (`/` encoded as
  `%2F` for scoped packages), using `dist-tags.latest`.
- **Advisories** — the GitHub Advisory Database REST API:
  `GET /advisories?affects={name}&ecosystem={eco}`. The `affects` parameter
  receives **only the package name** (e.g. `guzzlehttp/guzzle`) — the
  ecosystem goes in its own parameter. Prefixing it (`composer:...`) returns
  `200` with a silently empty list.
- **Semver** — comparisons and range satisfaction use `composer/semver`,
  including GHSA ranges where a comma means logical AND
  (e.g. `>= 7.0.0, < 7.4.5`).
- **Cache** — registry/advisory responses are cached to disk with a
  configurable TTL so repeated runs don't hit the API rate limits.

## Keep the CLI up to date

When installed from the released PHAR:

```bash
secure-lock self-update          # download and install the latest release
secure-lock self-update --check  # only check, don't install
```

When installed via Composer:

```bash
composer global update jeffersongoncalves/secure-lock-cli
```

## Development

```bash
composer install
composer test       # Pest tests + Pint lint
composer lint       # Auto-fix style
composer build      # Build the PHAR into builds/secure-lock
```

HTTP calls are mocked in the test suite with `Http::fake()`. Fixture
lockfiles created during tests live under `tests/tmp/` (gitignored).

## Release

1. Merge changes to `main` — CI builds a fresh `builds/secure-lock` against
   the latest tag and commits it back.
2. Create a new GitHub release (tag `X.Y.Z`, no `v` prefix).
3. The `publish-phar.yml` workflow attaches `secure-lock.phar` to the release
   and `update-changelog.yml` updates `CHANGELOG.md` + `version.txt`.

## Roadmap

- `--fix` flag to emit the `composer require` / `npm install` commands that
  pull the minimum patched versions leaving every vulnerable range.
- Packagist Security Advisories API as a redundant advisory backend when the
  GitHub rate limit tightens.
