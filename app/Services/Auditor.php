<?php

declare(strict_types=1);

namespace App\Services;

use App\Enums\Verdict;
use App\Support\Advisory;
use App\Support\AuditResult;
use App\Support\IgnoreList;
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
    public function run(array $packages, ?IgnoreList $ignore = null, ?Closure $onProgress = null): array
    {
        $ignore ??= IgnoreList::empty();
        $results = [];

        foreach ($packages as $package) {
            $package->latest = $this->registry->latest($package);

            $lookup = $this->advisories->forPackage($package);
            $package->advisoriesFailed = $lookup->failed;

            // Suppress accepted/ignored advisories before classifying.
            $package->advisories = $ignore->isEmpty()
                ? $lookup->advisories
                : array_values(array_filter(
                    $lookup->advisories,
                    fn (Advisory $a): bool => ! $ignore->matches($a),
                ));

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
        // A failed advisory lookup means the status cannot be trusted — never
        // let it masquerade as OK/SAFE.
        if ($package->advisoriesFailed) {
            return new AuditResult($package, Verdict::Unknown, [], [], unverified: true);
        }

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
