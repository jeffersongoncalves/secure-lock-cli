<?php

declare(strict_types=1);

namespace App\Services;

use App\Enums\Severity;
use App\Support\Advisory;
use App\Support\AdvisoryResult;
use App\Support\Package;

/**
 * Redundant advisory source for the npm ecosystem (npm/pnpm/bun/yarn) backed
 * by the npm registry's audit bulk endpoint. Used as a fallback when the
 * GitHub lookup fails, so the JS managers can be audited without a token too.
 *
 * The bulk endpoint only returns advisories matching the versions posted, so
 * both the installed and the latest version are sent per package — letting
 * Advisory::affects() recompute the verdict for current and latest alike.
 */
final class NpmAdvisoryClient
{
    private const ENDPOINT = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk';

    public function __construct(
        private readonly HttpFetcher $fetcher,
    ) {}

    /**
     * @param  list<Package>  $packages
     * @return array<string, AdvisoryResult> keyed by package name
     */
    public function forPackages(array $packages): array
    {
        if ($packages === []) {
            return [];
        }

        $body = [];

        foreach ($packages as $package) {
            $versions = array_values(array_unique(array_filter([
                $package->current,
                $package->latest,
            ], fn (?string $v): bool => is_string($v) && $v !== '')));

            if ($versions !== []) {
                $body[$package->name] = $versions;
            }
        }

        if ($body === []) {
            return [];
        }

        $outcome = $this->fetcher->post($this->endpoint(), $body, [
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
        ]);

        $results = [];

        foreach ($packages as $package) {
            if ($outcome['failed']) {
                $results[$package->name] = new AdvisoryResult([], failed: true, reason: $outcome['reason']);

                continue;
            }

            $entries = $outcome['data'][$package->name] ?? [];
            $results[$package->name] = new AdvisoryResult(is_array($entries) ? $this->parse($entries) : []);
        }

        return $results;
    }

    public function endpoint(): string
    {
        return self::ENDPOINT;
    }

    /**
     * @param  array<mixed>  $entries
     * @return list<Advisory>
     */
    private function parse(array $entries): array
    {
        $advisories = [];

        foreach ($entries as $entry) {
            if (! is_array($entry)) {
                continue;
            }

            $advisory = $this->makeAdvisory($entry);

            if ($advisory !== null) {
                $advisories[] = $advisory;
            }
        }

        return $advisories;
    }

    /**
     * @param  array<string, mixed>  $entry
     */
    private function makeAdvisory(array $entry): ?Advisory
    {
        $range = $entry['vulnerable_versions'] ?? null;

        if (! is_string($range) || $range === '') {
            return null;
        }

        $cve = null;
        $cves = $entry['cves'] ?? null;

        if (is_array($cves) && isset($cves[0]) && is_string($cves[0]) && $cves[0] !== '') {
            $cve = $cves[0];
        }

        $url = $entry['url'] ?? null;
        $ghsa = is_string($url) && str_contains($url, 'GHSA-') ? substr($url, (int) strpos($url, 'GHSA-')) : null;
        $id = $ghsa ?? 'NPM-'.(string) ($entry['id'] ?? '');

        return new Advisory(
            id: $id,
            title: is_string($entry['title'] ?? null) ? $entry['title'] : '',
            severity: Severity::fromGitHub(is_string($entry['severity'] ?? null) ? $entry['severity'] : null),
            vulnerableRanges: [$range],
            patchedVersions: [],
            cve: $cve,
            link: is_string($url) ? $url : null,
        );
    }
}
