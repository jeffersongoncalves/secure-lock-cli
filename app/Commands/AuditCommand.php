<?php

declare(strict_types=1);

namespace App\Commands;

use App\Enums\Ecosystem;
use App\Enums\Verdict;
use App\Services\AdvisoryClient;
use App\Services\Auditor;
use App\Services\LockReader;
use App\Services\RegistryClient;
use App\Support\AuditResult;
use App\Support\HttpCache;
use App\Support\Package;
use LaravelZero\Framework\Commands\Command;
use RuntimeException;

class AuditCommand extends Command
{
    protected $signature = 'audit
        {--dir= : Project directory (defaults to the current working directory)}
        {--composer= : Explicit path to composer.lock}
        {--npm= : Explicit path to package-lock.json}
        {--only-vuln : Show only packages that are at risk}
        {--no-dev : Ignore development dependencies}
        {--json : Structured JSON output (for CI)}
        {--github-token= : GitHub token (or the GITHUB_TOKEN env var)}
        {--cache-ttl=3600 : HTTP cache TTL in seconds (0 disables caching)}';

    protected $description = 'Audit Composer and npm dependencies for known vulnerabilities and safe updates';

    public function handle(LockReader $reader): int
    {
        $json = (bool) $this->option('json');

        try {
            $packages = $this->readPackages($reader);
        } catch (RuntimeException $e) {
            $this->reportInputError($e->getMessage(), $json);

            return 2;
        }

        if ($packages === []) {
            $this->reportInputError('No lockfile found. Looked for composer.lock and package-lock.json.', $json);

            return 2;
        }

        if ($this->option('no-dev')) {
            $packages = array_values(array_filter($packages, fn (Package $p): bool => ! $p->isDev));
        }

        $auditor = $this->makeAuditor();
        $results = $this->audit($auditor, $packages, $json);

        if ($json) {
            $this->renderJson($results);
        } else {
            $this->renderTable($results);
            $this->renderSummary($results);
        }

        return $this->exitCode($results);
    }

    /**
     * @return list<Package>
     */
    private function readPackages(LockReader $reader): array
    {
        $packages = [];

        $composerPath = $this->resolveLockPath('composer', Ecosystem::Composer);

        if ($composerPath !== null) {
            $packages = [...$packages, ...$reader->readComposer($composerPath)];
        }

        $npmPath = $this->resolveLockPath('npm', Ecosystem::Npm);

        if ($npmPath !== null) {
            $packages = [...$packages, ...$reader->readNpm($npmPath)];
        }

        return $packages;
    }

    /**
     * Resolution order: explicit flag > --dir > current working directory.
     */
    private function resolveLockPath(string $option, Ecosystem $ecosystem): ?string
    {
        $explicit = $this->option($option);

        if (is_string($explicit) && $explicit !== '') {
            if (! is_file($explicit)) {
                throw new RuntimeException("Lockfile not found: {$explicit}");
            }

            return $explicit;
        }

        $dir = $this->option('dir');
        $base = is_string($dir) && $dir !== '' ? $dir : getcwd();

        $path = rtrim((string) $base, '/\\').DIRECTORY_SEPARATOR.$ecosystem->lockFileName();

        return is_file($path) ? $path : null;
    }

    private function makeAuditor(): Auditor
    {
        $ttl = (int) $this->option('cache-ttl');
        $token = $this->option('github-token');

        if (! is_string($token) || $token === '') {
            $token = getenv('GITHUB_TOKEN') ?: null;
        }

        $cache = new HttpCache($this->cacheDirectory(), $ttl);

        return new Auditor(
            new RegistryClient($cache),
            new AdvisoryClient($cache, is_string($token) ? $token : null),
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
    private function audit(Auditor $auditor, array $packages, bool $json): array
    {
        if ($json) {
            return $auditor->run($packages);
        }

        $bar = $this->output->createProgressBar(count($packages));
        $bar->setFormat(' %current%/%max% [%bar%] %message%');
        $bar->setMessage('');
        $bar->start();

        $results = $auditor->run($packages, function (Package $package) use ($bar): void {
            $bar->setMessage($package->ecosystem->label().':'.$package->name);
            $bar->advance();
        });

        $bar->finish();
        $this->newLine(2);

        return $results;
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
                $result->package->ecosystem->label(),
                $result->package->name,
                $result->package->current,
                $result->package->latest ?? '-',
                $this->observation($result),
            ];
        }

        $this->table(
            ['STATUS', 'ECO', 'PACOTE', 'ATUAL', 'ÚLTIMA', 'OBSERVAÇÃO'],
            $rows,
        );
    }

    private function observation(AuditResult $result): string
    {
        $advisory = $result->topAdvisory();

        if ($advisory === null) {
            return $result->package->hasUpdate() ? 'update disponível' : '-';
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
        $counts = [
            Verdict::Vuln->value => 0,
            Verdict::RiskyUpdate->value => 0,
            Verdict::SafeUpdate->value => 0,
            Verdict::Update->value => 0,
            Verdict::Ok->value => 0,
        ];

        foreach ($results as $result) {
            $counts[$result->verdict->value]++;
        }

        $this->newLine();
        $this->line(sprintf(
            '  <fg=red>%d vulneráveis agora</>  ·  <fg=magenta>%d update arriscado</>  ·  <fg=green>%d update seguro</>  ·  <fg=cyan>%d update disponível</>  ·  <fg=gray>%d atualizado e seguro</>',
            $counts[Verdict::Vuln->value],
            $counts[Verdict::RiskyUpdate->value],
            $counts[Verdict::SafeUpdate->value],
            $counts[Verdict::Update->value],
            $counts[Verdict::Ok->value],
        ));
        $this->newLine();
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

        $payload = array_map(fn (AuditResult $r): array => $r->toArray(), $results);

        $this->output->writeln((string) json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
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
        foreach ($results as $result) {
            if ($result->verdict->failsCi()) {
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
