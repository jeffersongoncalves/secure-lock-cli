<?php

declare(strict_types=1);

namespace App\Services;

use App\Enums\Verdict;
use App\Support\AuditResult;
use App\Support\Package;
use Closure;

/**
 * Orchestrates the audit: enriches each package with its latest version and
 * advisories, then classifies it into a verdict.
 */
final class Auditor
{
    public function __construct(
        private readonly RegistryClient $registry,
        private readonly AdvisoryClient $advisories,
    ) {}

    /**
     * @param  list<Package>  $packages
     * @param  (Closure(Package): void)|null  $onProgress  Called after each package is processed.
     * @return list<AuditResult>
     */
    public function run(array $packages, ?Closure $onProgress = null): array
    {
        $results = [];

        foreach ($packages as $package) {
            $package->latest = $this->registry->latest($package);
            $package->advisories = $this->advisories->forPackage($package);

            $results[] = $this->classify($package);

            if ($onProgress !== null) {
                $onProgress($package);
            }
        }

        return $results;
    }

    /**
     * Apply the classification table to an already-enriched package.
     */
    public function classify(Package $package): AuditResult
    {
        $vulnNow = $package->currentVulnerabilities();
        $vulnLatest = $package->vulnerabilitiesInLatest();
        $hasUpdate = $package->hasUpdate();

        if ($vulnNow !== []) {
            $verdict = match (true) {
                ! $hasUpdate => Verdict::Vuln,
                $vulnLatest === [] => Verdict::SafeUpdate,
                default => Verdict::RiskyUpdate,
            };
        } else {
            $verdict = match (true) {
                ! $hasUpdate => Verdict::Ok,
                $vulnLatest === [] => Verdict::Update,
                default => Verdict::RiskyUpdate,
            };
        }

        return new AuditResult($package, $verdict, $vulnNow, $vulnLatest);
    }
}
