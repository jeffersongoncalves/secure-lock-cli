<?php

declare(strict_types=1);

namespace App\Commands;

use App\Enums\Verdict;
use App\Services\AdvisoryClient;
use App\Services\Auditor;
use App\Services\Fixer;
use App\Services\HttpFetcher;
use App\Services\LockReader;
use App\Services\RegistryClient;
use App\Services\SarifReporter;
use App\Support\AuditResult;
use App\Support\HttpCache;
use App\Support\IgnoreList;
use App\Support\Package;
use LaravelZero\Framework\Commands\Command;
use RuntimeException;

class AuditCommand extends Command
{
    protected $signature = 'audit
        {--dir= : Project directory (defaults to the current working directory)}
        {--composer= : Explicit path to composer.lock}
        {--npm= : Explicit path to package-lock.json}
        {--pnpm= : Explicit path to pnpm-lock.yaml}
        {--bun= : Explicit path to bun.lock}
        {--yarn= : Explicit path to yarn.lock}
        {--only-vuln : Show only packages that are at risk}
        {--fix : Print upgrade commands that leave every vulnerable range}
        {--no-dev : Ignore development dependencies}
        {--ignore=* : Advisory id (GHSA or CVE) to suppress; repeatable}
        {--config= : Path to a secure-lock.json config (auto-detected otherwise)}
        {--fail-on-unverified : Exit non-zero when an advisory lookup fails}
        {--json : Structured JSON output (for CI)}
        {--sarif : SARIF 2.1.0 output (for GitHub code scanning)}
        {--github-token= : GitHub token (or the GITHUB_TOKEN env var)}
        {--cache-ttl=3600 : HTTP cache TTL in seconds (0 disables caching)}';

    protected $description = 'Audit Composer, npm, pnpm, bun and yarn dependencies for known vulnerabilities and safe updates';

    public function handle(LockReader $reader): int
    {
        $json = (bool) $this->option('json');
        $sarif = (bool) $this->option('sarif');
        $machine = $json || $sarif;

        try {
            $packages = $this->readPackages($reader);
            $ignore = $this->buildIgnoreList();
        } catch (RuntimeException $e) {
            $this->reportInputError($e->getMessage(), $machine);

            return 2;
        }

        if ($packages === []) {
            $this->reportInputError('No lockfile found. Looked for composer.lock, pnpm-lock.yaml, bun.lock, yarn.lock and package-lock.json.', $machine);

            return 2;
        }

        if ($this->option('no-dev')) {
            $packages = array_values(array_filter($packages, fn (Package $p): bool => ! $p->isDev));
        }

        $auditor = $this->makeAuditor();
        $results = $this->audit($auditor, $packages, $ignore, $machine);

        if ($sarif) {
            $this->renderSarif($results);
        } elseif ($json) {
            $this->renderJson($results);
        } else {
            $this->renderTable($results);
            $this->renderSummary($results);

            if ($this->option('fix')) {
                $this->renderFixes($results);
            }
        }

        return $this->exitCode($results);
    }

    /**
     * @return list<Package>
     */
    private function readPackages(LockReader $reader): array
    {
        $packages = [];

        $composerPath = $this->resolveComposerPath();

        if ($composerPath !== null) {
            $packages = [...$packages, ...$reader->readComposer($composerPath)];
        }

        foreach ($this->resolveJsLocks() as [$manager, $path]) {
            $packages = [...$packages, ...match ($manager) {
                'npm' => $reader->readNpm($path),
                'pnpm' => $reader->readPnpm($path),
                'bun' => $reader->readBun($path),
                'yarn' => $reader->readYarn($path),
                default => [],
            }];
        }

        return $packages;
    }

    /**
     * Resolution order: --composer flag > --dir/cwd composer.lock.
     */
    private function resolveComposerPath(): ?string
    {
        $explicit = $this->option('composer');

        if (is_string($explicit) && $explicit !== '') {
            if (! is_file($explicit)) {
                throw new RuntimeException("Lockfile not found: {$explicit}");
            }

            return $explicit;
        }

        return $this->lockInBaseDir('composer.lock');
    }

    /**
     * Resolve the JavaScript lockfile(s) to read.
     *
     * Explicit --npm/--pnpm/--bun flags win (each read if given). Otherwise a
     * single lockfile is auto-detected in the project directory by priority:
     * pnpm > bun > npm — since a project uses one JS package manager.
     *
     * @return list<array{0: string, 1: string}> list of [manager, path]
     */
    private function resolveJsLocks(): array
    {
        $explicit = [];

        foreach (['npm', 'pnpm', 'bun', 'yarn'] as $manager) {
            $path = $this->option($manager);

            if (is_string($path) && $path !== '') {
                if (! is_file($path)) {
                    throw new RuntimeException("Lockfile not found: {$path}");
                }

                $explicit[] = [$manager, $path];
            }
        }

        if ($explicit !== []) {
            return $explicit;
        }

        foreach (['pnpm' => 'pnpm-lock.yaml', 'bun' => 'bun.lock', 'yarn' => 'yarn.lock', 'npm' => 'package-lock.json', 'npm-shrinkwrap' => 'npm-shrinkwrap.json'] as $manager => $file) {
            $path = $this->lockInBaseDir($file);

            if ($path !== null) {
                return [[$manager === 'npm-shrinkwrap' ? 'npm' : $manager, $path]];
            }
        }

        return [];
    }

    private function lockInBaseDir(string $file): ?string
    {
        $dir = $this->option('dir');
        $base = is_string($dir) && $dir !== '' ? $dir : getcwd();

        $path = rtrim((string) $base, '/\\').DIRECTORY_SEPARATOR.$file;

        return is_file($path) ? $path : null;
    }

    private function makeAuditor(): Auditor
    {
        $ttl = (int) $this->option('cache-ttl');
        $token = $this->option('github-token');

        if (! is_string($token) || $token === '') {
            $token = getenv('GITHUB_TOKEN') ?: null;
        }

        $fetcher = new HttpFetcher(new HttpCache($this->cacheDirectory(), $ttl));

        return new Auditor(
            new RegistryClient($fetcher),
            new AdvisoryClient($fetcher, is_string($token) ? $token : null),
            $fetcher,
        );
    }

    private function cacheDirectory(): string
    {
        return sys_get_temp_dir().DIRECTORY_SEPARATOR.'secure-lock-cache';
    }

    /**
     * @param  list<Package>  $packages
     * @return list<AuditResult>
     */
    private function audit(Auditor $auditor, array $packages, IgnoreList $ignore, bool $quiet): array
    {
        if ($quiet) {
            return $auditor->run($packages, $ignore);
        }

        $bar = $this->output->createProgressBar(count($packages));
        $bar->setFormat(' %current%/%max% [%bar%] %message%');
        $bar->setMessage('');
        $bar->start();

        $results = $auditor->run($packages, $ignore, function (Package $package) use ($bar): void {
            $bar->setMessage($package->manager().':'.$package->name);
            $bar->advance();
        });

        $bar->finish();
        $this->newLine(2);

        return $results;
    }

    /**
     * Build the advisory ignore list from --ignore flags plus a
     * secure-lock.json config (--config or auto-detected in the project dir).
     */
    private function buildIgnoreList(): IgnoreList
    {
        $flags = (array) $this->option('ignore');
        $entries = array_values(array_filter($flags, fn ($v): bool => is_string($v) && $v !== ''));

        $configPath = $this->resolveConfigPath();

        if ($configPath !== null) {
            $raw = file_get_contents($configPath);
            $config = $raw === false ? null : json_decode($raw, true);

            if (! is_array($config)) {
                throw new RuntimeException("Invalid JSON in config: {$configPath}");
            }

            foreach ((array) ($config['ignore'] ?? []) as $entry) {
                $entries[] = $entry;
            }
        }

        return $entries === [] ? IgnoreList::empty() : IgnoreList::fromEntries($entries, date('Y-m-d'));
    }

    private function resolveConfigPath(): ?string
    {
        $explicit = $this->option('config');

        if (is_string($explicit) && $explicit !== '') {
            if (! is_file($explicit)) {
                throw new RuntimeException("Config not found: {$explicit}");
            }

            return $explicit;
        }

        return $this->lockInBaseDir('secure-lock.json');
    }

    /**
     * @param  list<AuditResult>  $results
     */
    private function renderTable(array $results): void
    {
        $results = $this->sortByRisk($results);

        if ($this->option('only-vuln')) {
            $results = array_values(array_filter(
                $results,
                fn (AuditResult $r): bool => $r->verdict !== Verdict::Ok && $r->verdict !== Verdict::Update,
            ));
        }

        if ($results === []) {
            $this->components->info('Nothing to display.');

            return;
        }

        $rows = [];

        foreach ($results as $result) {
            $rows[] = [
                $result->verdict->badge(),
                $result->package->manager(),
                $result->package->name,
                $result->package->current,
                $result->package->latest ?? '-',
                $this->observation($result),
            ];
        }

        $this->table(
            ['STATUS', 'ECO', 'PACKAGE', 'CURRENT', 'LATEST', 'NOTE'],
            $rows,
        );
    }

    private function observation(AuditResult $result): string
    {
        $advisory = $result->topAdvisory();

        if ($advisory === null) {
            return $result->package->hasUpdate() ? 'update available' : '-';
        }

        $extra = count($result->relevantAdvisories()) - 1;

        $text = strtoupper($advisory->severity->value).' '.$advisory->identifier();

        if ($extra > 0) {
            $text .= " (+{$extra})";
        }

        return $text;
    }

    /**
     * @param  list<AuditResult>  $results
     */
    private function renderSummary(array $results): void
    {
        $counts = array_fill_keys(array_map(fn (Verdict $v): string => $v->value, Verdict::cases()), 0);

        foreach ($results as $result) {
            $counts[$result->verdict->value]++;
        }

        $this->newLine();
        $this->line(sprintf(
            '  <fg=red>%d vulnerable now</>  ·  <fg=magenta>%d risky update</>  ·  <fg=yellow>%d unverified</>  ·  <fg=green>%d safe update</>  ·  <fg=cyan>%d update available</>  ·  <fg=gray>%d up to date</>',
            $counts[Verdict::Vuln->value],
            $counts[Verdict::RiskyUpdate->value],
            $counts[Verdict::Unknown->value],
            $counts[Verdict::SafeUpdate->value],
            $counts[Verdict::Update->value],
            $counts[Verdict::Ok->value],
        ));
        $this->newLine();

        if ($counts[Verdict::Unknown->value] > 0) {
            $this->components->warn(sprintf(
                '%d package(s) could not be verified (advisory lookup failed). Set a GITHUB_TOKEN to raise the rate limit and re-run.',
                $counts[Verdict::Unknown->value],
            ));
        }
    }

    /**
     * @param  list<AuditResult>  $results
     */
    private function renderSarif(array $results): void
    {
        $sarif = (new SarifReporter)->build(
            $this->sortByRisk($results),
            (string) config('app.version', 'unreleased'),
        );

        $this->output->writeln((string) json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    /**
     * @param  list<AuditResult>  $results
     */
    private function renderJson(array $results): void
    {
        $results = $this->sortByRisk($results);

        if ($this->option('only-vuln')) {
            $results = array_values(array_filter(
                $results,
                fn (AuditResult $r): bool => $r->verdict !== Verdict::Ok && $r->verdict !== Verdict::Update,
            ));
        }

        $fix = (bool) $this->option('fix');
        $fixer = new Fixer;

        $payload = array_map(function (AuditResult $r) use ($fix, $fixer): array {
            $row = $r->toArray();

            if ($fix) {
                $row['fix'] = $fixer->suggest($r)?->toArray();
            }

            return $row;
        }, $results);

        $this->output->writeln((string) json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    /**
     * @param  list<AuditResult>  $results
     */
    private function renderFixes(array $results): void
    {
        $fixer = new Fixer;
        $commands = [];

        foreach ($this->sortByRisk($results) as $result) {
            $suggestion = $fixer->suggest($result);

            if ($suggestion !== null) {
                $commands[] = $suggestion->command;
            }
        }

        $this->newLine();

        if ($commands === []) {
            $this->components->info('No automatic fix available.');

            return;
        }

        $this->line('  <fg=yellow;options=bold>Suggested fixes:</>');
        $this->newLine();

        foreach ($commands as $command) {
            $this->line("  <fg=green>{$command}</>");
        }

        $this->newLine();
    }

    /**
     * @param  list<AuditResult>  $results
     * @return list<AuditResult>
     */
    private function sortByRisk(array $results): array
    {
        usort($results, function (AuditResult $a, AuditResult $b): int {
            return $b->verdict->riskOrder() <=> $a->verdict->riskOrder()
                ?: strcmp($a->package->name, $b->package->name);
        });

        return $results;
    }

    /**
     * @param  list<AuditResult>  $results
     */
    private function exitCode(array $results): int
    {
        $failOnUnverified = (bool) $this->option('fail-on-unverified');

        foreach ($results as $result) {
            if ($result->verdict->failsCi()) {
                return 1;
            }

            if ($failOnUnverified && $result->unverified) {
                return 1;
            }
        }

        return 0;
    }

    private function reportInputError(string $message, bool $json): void
    {
        if ($json) {
            $this->output->writeln((string) json_encode(['error' => $message], JSON_PRETTY_PRINT));

            return;
        }

        $this->components->error($message);
    }
}
