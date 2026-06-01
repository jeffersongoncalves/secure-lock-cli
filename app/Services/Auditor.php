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
 * advisories, then classifies it into a verdict. Registry and advisory
 * lookups for every package are fired concurrently in one wave.
 */
final class Auditor
{
    public function __construct(
        private readonly RegistryClient $registry,
        private readonly AdvisoryClient $advisories,
        private readonly HttpFetcher $fetcher,
    ) {}

    /**
     * @param  list<Package>  $packages
     * @param  (Closure(Package): void)|null  $onProgress  Called after each package is processed.
     * @return list<AuditResult>
     */
    public function run(array $packages, ?IgnoreList $ignore = null, ?Closure $onProgress = null): array
    {
        $ignore ??= IgnoreList::empty();

        // One concurrent wave for every package's registry + first advisory page.
        $requests = [];

        foreach ($packages as $i => $package) {
            $requests["reg:$i"] = ['url' => $this->registry->url($package), 'headers' => ['Accept' => 'application/json']];
            $requests["adv:$i"] = ['url' => $this->advisories->url($package->name, $package->ecosystem, 1), 'headers' => $this->advisories->headers()];
        }

        $outcomes = $this->fetcher->many($requests);

        $results = [];

        foreach ($packages as $i => $package) {
            $package->latest = $this->registry->extractLatest($package, $outcomes["reg:$i"]);

            // Resume advisory collection from the pooled first page (paginates
            // sequentially only for the rare package with >100 advisories).
            $lookup = $this->advisories->collect($package->name, $package->ecosystem, $outcomes["adv:$i"], fromPage: 2);
            $package->advisoriesFailed = $lookup->failed;

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
