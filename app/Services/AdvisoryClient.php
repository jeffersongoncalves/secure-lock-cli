<?php

declare(strict_types=1);

namespace App\Services;

use App\Enums\Ecosystem;
use App\Enums\Severity;
use App\Support\Advisory;
use App\Support\AdvisoryResult;
use App\Support\Package;

/**
 * Fetches advisories for a package from the GitHub Advisory Database.
 */
final class AdvisoryClient
{
    private const PER_PAGE = 100;

    private const MAX_PAGES = 10;

    public function __construct(
        private readonly HttpFetcher $fetcher,
        private readonly ?string $token = null,
    ) {}

    public function forPackage(Package $package): AdvisoryResult
    {
        return $this->forName($package->name, $package->ecosystem);
    }

    public function forName(string $name, Ecosystem $ecosystem): AdvisoryResult
    {
        $first = $this->fetcher->fetch($this->url($name, $ecosystem, 1), $this->headers());

        return $this->collect($name, $ecosystem, $first, fromPage: 2);
    }

    /**
     * Continue collecting from an already-fetched first page (used by the
     * batch path, which pools every package's first page concurrently).
     *
     * @param  array{failed: bool, data: array<mixed>|null, reason: ?string}  $first
     */
    public function collect(string $name, Ecosystem $ecosystem, array $first, int $fromPage): AdvisoryResult
    {
        if ($first['failed']) {
            return new AdvisoryResult([], failed: true, reason: $first['reason']);
        }

        $advisories = $this->parsePage($first['data'], $name, $ecosystem);

        // Only paginate when the first page came back full.
        if ($this->isFullPage($first['data'])) {
            for ($page = $fromPage; $page <= self::MAX_PAGES; $page++) {
                $outcome = $this->fetcher->fetch($this->url($name, $ecosystem, $page), $this->headers());

                if ($outcome['failed']) {
                    return new AdvisoryResult($advisories, failed: true, reason: $outcome['reason']);
                }

                $advisories = [...$advisories, ...$this->parsePage($outcome['data'], $name, $ecosystem)];

                if (! $this->isFullPage($outcome['data'])) {
                    break;
                }
            }
        }

        return new AdvisoryResult($advisories);
    }

    /**
     * CRITICAL: "affects" takes ONLY the package name. Prefixing it with the
     * ecosystem (e.g. "composer:guzzlehttp/guzzle") returns 200 with an empty
     * list. The ecosystem goes in its own parameter.
     */
    public function url(string $name, Ecosystem $ecosystem, int $page = 1): string
    {
        return 'https://api.github.com/advisories?'.http_build_query([
            'affects' => $name,
            'ecosystem' => $ecosystem->advisoryName(),
            'per_page' => self::PER_PAGE,
            'page' => $page,
        ]);
    }

    /**
     * @return array<string, string>
     */
    public function headers(): array
    {
        $headers = ['Accept' => 'application/vnd.github+json'];

        if ($this->token !== null && $this->token !== '') {
            $headers['Authorization'] = 'Bearer '.$this->token;
        }

        return $headers;
    }

    /**
     * @param  array<mixed>|null  $data
     * @return list<Advisory>
     */
    public function parsePage(?array $data, string $name, Ecosystem $ecosystem): array
    {
        if (! is_array($data)) {
            return [];
        }

        $advisories = [];

        foreach ($data as $entry) {
            if (! is_array($entry)) {
                continue;
            }

            $advisory = $this->makeAdvisory($entry, $name, $ecosystem);

            if ($advisory !== null) {
                $advisories[] = $advisory;
            }
        }

        return $advisories;
    }

    /**
     * @param  array<mixed>|null  $data
     */
    private function isFullPage(?array $data): bool
    {
        return is_array($data) && count($data) >= self::PER_PAGE;
    }

    /**
     * @param  array<string, mixed>  $entry
     */
    private function makeAdvisory(array $entry, string $name, Ecosystem $ecosystem): ?Advisory
    {
        $ranges = [];
        $patched = [];

        foreach ($entry['vulnerabilities'] ?? [] as $vulnerability) {
            if (! is_array($vulnerability)) {
                continue;
            }

            $package = $vulnerability['package'] ?? null;

            if (! is_array($package) || ($package['name'] ?? null) !== $name) {
                continue;
            }

            $packageEcosystem = $package['ecosystem'] ?? null;

            if (is_string($packageEcosystem) && strtolower($packageEcosystem) !== $ecosystem->advisoryName()) {
                continue;
            }

            $range = $vulnerability['vulnerable_version_range'] ?? null;

            if (is_string($range) && $range !== '') {
                $ranges[] = $range;
            }

            $firstPatched = $vulnerability['first_patched_version'] ?? null;

            if (is_array($firstPatched)) {
                $firstPatched = $firstPatched['identifier'] ?? null;
            }

            if (is_string($firstPatched) && $firstPatched !== '') {
                $patched[] = $firstPatched;
            }
        }

        // No range hit this package — the advisory is not relevant.
        if ($ranges === []) {
            return null;
        }

        return new Advisory(
            id: is_string($entry['ghsa_id'] ?? null) ? $entry['ghsa_id'] : '',
            title: is_string($entry['summary'] ?? null) ? $entry['summary'] : '',
            severity: Severity::fromGitHub($entry['severity'] ?? null),
            vulnerableRanges: array_values(array_unique($ranges)),
            patchedVersions: array_values(array_unique($patched)),
            cve: is_string($entry['cve_id'] ?? null) ? $entry['cve_id'] : null,
            link: is_string($entry['html_url'] ?? null) ? $entry['html_url'] : null,
        );
    }
}
