<?php

declare(strict_types=1);

namespace App\Services;

use App\Enums\Severity;
use App\Support\Advisory;
use App\Support\AdvisoryResult;

/**
 * Redundant advisory source backed by the Packagist Security Advisories API.
 * Used as a fallback for Composer packages when the GitHub lookup fails (most
 * often a rate limit), so a missing token no longer leaves packages unverified.
 *
 * Composer only — Packagist does not serve npm advisories. The API accepts
 * many packages[] in a single request, so the whole fallback set is one call.
 */
final class PackagistAdvisoryClient
{
    /**
     * Packages per request — bounds the GET query-string length and keeps a
     * single failure from leaving every package unverified.
     */
    private const BATCH = 80;

    public function __construct(
        private readonly HttpFetcher $fetcher,
    ) {}

    /**
     * @param  list<string>  $names
     * @return array<string, AdvisoryResult> keyed by package name
     */
    public function forComposerPackages(array $names): array
    {
        $results = [];

        foreach (array_chunk(array_values(array_unique($names)), self::BATCH) as $batch) {
            foreach ($this->fetchBatch($batch) as $name => $result) {
                $results[$name] = $result;
            }
        }

        return $results;
    }

    /**
     * @param  list<string>  $names
     * @return array<string, AdvisoryResult>
     */
    private function fetchBatch(array $names): array
    {
        $query = implode('&', array_map(
            static fn (string $name): string => 'packages[]='.rawurlencode($name),
            $names,
        ));

        $outcome = $this->fetcher->fetch(
            'https://packagist.org/api/security-advisories/?'.$query,
            ['Accept' => 'application/json'],
        );

        $results = [];

        foreach ($names as $name) {
            if ($outcome['failed']) {
                $results[$name] = new AdvisoryResult([], failed: true, reason: $outcome['reason']);

                continue;
            }

            $entries = $outcome['data']['advisories'][$name] ?? [];
            $results[$name] = new AdvisoryResult(is_array($entries) ? $this->parse($entries) : []);
        }

        return $results;
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
        $affected = $entry['affectedVersions'] ?? null;

        if (! is_string($affected) || $affected === '') {
            return null;
        }

        // affectedVersions is a composer constraint where "|" means OR; each
        // alternative becomes its own vulnerable range.
        $ranges = array_values(array_filter(array_map('trim', explode('|', $affected))));

        if ($ranges === []) {
            return null;
        }

        $cve = $entry['cve'] ?? null;

        return new Advisory(
            id: is_string($entry['advisoryId'] ?? null) ? $entry['advisoryId'] : '',
            title: is_string($entry['title'] ?? null) ? $entry['title'] : '',
            severity: Severity::fromGitHub(is_string($entry['severity'] ?? null) ? $entry['severity'] : null),
            vulnerableRanges: $ranges,
            patchedVersions: [],
            cve: is_string($cve) && $cve !== '' ? $cve : null,
            link: is_string($entry['link'] ?? null) ? $entry['link'] : null,
        );
    }
}
