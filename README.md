<div class="filament-hidden">

![Secure Lock CLI](https://raw.githubusercontent.com/jeffersongoncalves/secure-lock-cli/main/art/jeffersongoncalves-secure-lock-cli.png)

</div>

# secure-lock-cli

`secure-lock` audits a project's dependencies and answers three questions
for every package:

1. **Is there a newer version?** (registry lookup)
2. **Is the installed version vulnerable?** (advisory database lookup)
3. **Is the available update actually safe?** — i.e. does the target version
   really leave the vulnerable range, instead of merely being newer?

Born out of the recent wave of supply-chain attacks (compromised /
vulnerable packages on Composer and npm), the tool distinguishes a *useful
bump that fixes the flaw* from a *useless bump that stays exposed*.

It covers **Composer** (`composer.lock`) and the JavaScript managers that
share the npm ecosystem: **npm** (`package-lock.json` v1/v2/v3 and
`npm-shrinkwrap.json`), **pnpm** (`pnpm-lock.yaml` lockfileVersion 5/6/9),
**bun** (`bun.lock` text lockfile) and **yarn** (`yarn.lock` classic v1 and
berry v2+). The `ECO` column shows the real manager a package came from, while
advisories and the registry are resolved against the shared npm ecosystem.

Built with [Laravel Zero](https://laravel-zero.com) and modeled on the
other CLIs in this monorepo.

![secure-lock audit](https://raw.githubusercontent.com/jeffersongoncalves/secure-lock-cli/main/art/screenshot-audit.png)

Every package is checked against the registry and the GitHub Advisory
Database, then classified — here six packages have a published fix (`SAFE`)
and one only has a newer release (`UPDATE`).

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
secure-lock --fix                # also print upgrade commands
```

The JavaScript lockfile is auto-detected in the project directory by priority
(`pnpm` > `bun` > `yarn` > `npm`); pass `--pnpm`/`--bun`/`--yarn`/`--npm` to
target one explicitly.

### Options

```
--dir=            Project directory (defaults to the current directory)
--composer=       Explicit path to composer.lock
--npm=            Explicit path to package-lock.json
--pnpm=           Explicit path to pnpm-lock.yaml
--bun=            Explicit path to bun.lock
--yarn=           Explicit path to yarn.lock
--only-vuln           Show only packages at risk
--fix                 Print upgrade commands that leave every vulnerable range
--no-dev              Ignore development dependencies
--ignore=             Advisory id (GHSA or CVE) to suppress; repeatable
--config=             Path to a secure-lock.json (auto-detected otherwise)
--fail-on-unverified  Exit non-zero when an advisory lookup fails
--json                Structured JSON output (for CI)
--sarif               SARIF 2.1.0 output (for GitHub code scanning)
--github-token=       GitHub token (or the GITHUB_TOKEN env var)
--cache-ttl=3600      HTTP cache TTL in seconds (0 disables caching)
```

## Verdicts

For each package the tool compares the advisories that hit the **current**
version against those still hitting the **latest** version:

| Verdict | Badge | Meaning |
|---------|-------|---------|
| `VULN` | `● VULN` (red) | vulnerable now, no published fix |
| `RISKY_UPDATE` | `● RISKY` (magenta) | an update exists but stays exposed |
| `UNKNOWN` | `● UNKNOWN` (yellow) | advisory lookup failed — status not verified |
| `SAFE_UPDATE` | `● SAFE` (green) | the update **fixes** the vulnerability |
| `UPDATE` | `● UPDATE` (cyan) | newer version, no known vulnerability |
| `OK` | `● OK` (gray) | up to date and clean |

The table is sorted by risk (`VULN` > `RISKY` > `UNKNOWN` > `SAFE` > `UPDATE` >
`OK`) and the `NOTE` column shows the highest-severity advisory as
`SEVERITY CVE-XXXX (+N)` (the CVE when present, otherwise the GHSA id).

> **`UNKNOWN` matters.** When an advisory lookup fails (most often the GitHub
> rate limit without a token), the package is reported as `UNKNOWN` — never as
> `OK`. A security tool must not turn a failed request into a false "all clear".
> Set a `GITHUB_TOKEN` to lift the limit, and add `--fail-on-unverified` to make
> CI fail when anything could not be checked.

## Fixing

Pass `--fix` to also print, per manager, the upgrade command for each
currently-vulnerable package. The target is the **smallest** version greater
than the installed one that escapes *every* vulnerable range (computed from the
advisories' patched versions and the latest release), so the bump is minimal
and verified — not just "the newest":

![secure-lock audit --fix](https://raw.githubusercontent.com/jeffersongoncalves/secure-lock-cli/main/art/screenshot-fix.png)

Note how the target is the *minimum* safe version, not the newest:
`guzzlehttp/guzzle` goes to `6.5.8` (not `7.10.5`) and `phpunit` to `9.6.33`.

Packages with no version that leaves the vulnerable range (`VULN`) are skipped.
In `--json` mode each package gains a `fix` object (`{target, command}`) or
`null`.

## Suppressing advisories

Accepted or un-patchable risks would otherwise keep failing CI forever. Pass
one or more `--ignore` flags, or commit a `secure-lock.json` to the project
root (auto-detected, or point at it with `--config`):

```jsonc
{
  "ignore": [
    "CVE-2022-31091",
    { "id": "GHSA-xxxx-yyyy-zzzz", "expires": "2026-12-31" }
  ]
}
```

```bash
secure-lock --ignore=GHSA-xxxx-yyyy-zzzz --ignore=CVE-2022-31091
```

An ignored advisory no longer counts toward the verdict. Entries with an
`expires` date stop suppressing once that date has passed, so a deferred risk
re-surfaces instead of being forgotten.

## GitHub code scanning (SARIF)

`--sarif` emits SARIF 2.1.0, which GitHub can ingest to show the findings in
the repository's **Security › Code scanning** tab:

```yaml
name: secure-lock
on: [push, pull_request]
permissions:
  security-events: write
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - run: composer global require jeffersongoncalves/secure-lock-cli
      - run: secure-lock --no-dev --sarif > results.sarif
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

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

- Packagist Security Advisories API as a redundant advisory backend when the
  GitHub rate limit tightens.
- Transitive-aware `--fix` (currently emits a direct `add`/`require` per
  vulnerable package).
