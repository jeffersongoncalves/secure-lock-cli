<?php

declare(strict_types=1);

namespace App\Services;

use App\Enums\Ecosystem;
use App\Enums\Severity;
use App\Support\Advisory;
use App\Support\HttpCache;
use App\Support\Package;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Fetches advisories for a package from the GitHub Advisory Database.
 */
final class AdvisoryClient
{
    public function __construct(
        private readonly HttpCache $cache,
        private readonly ?string $token = null,
        private readonly int $timeout = 15,
    ) {}

    /**
     * @return list<Advisory>
     */
    public function forPackage(Package $package): array
    {
        return $this->forName($package->name, $package->ecosystem);
    }

    /**
     * @return list<Advisory>
     */
    public function forName(string $name, Ecosystem $ecosystem): array
    {
        // CRITICAL: "affects" takes ONLY the package name. Prefixing it with
        // the ecosystem (e.g. "composer:guzzlehttp/guzzle") returns 200 with
        // an empty list. The ecosystem goes in its own parameter.
        $url = 'https://api.github.com/advisories?'.http_build_query([
            'affects' => $name,
            'ecosystem' => $ecosystem->advisoryName(),
            'per_page' => 100,
        ]);

        $data = $this->get($url);

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

            $package = $vulnerability['package'] ?? [];
            $packageName = is_array($package) ? ($package['name'] ?? null) : null;

            if ($packageName !== $name) {
                continue;
            }

            $packageEcosystem = is_array($package) ? ($package['ecosystem'] ?? null) : null;

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

    /**
     * @return array<int, mixed>|null
     */
    private function get(string $url): ?array
    {
        $result = $this->cache->remember($url, function () use ($url): ?array {
            try {
                $response = Http::timeout($this->timeout)
                    ->retry(2, 200, throw: false)
                    ->withHeaders($this->headers())
                    ->get($url);
            } catch (Throwable) {
                return null;
            }

            if (! $response->successful()) {
                return null;
            }

            $json = $response->json();

            return is_array($json) ? $json : null;
        });

        return is_array($result) ? $result : null;
    }

    /**
     * @return array<string, string>
     */
    private function headers(): array
    {
        $headers = ['Accept' => 'application/vnd.github+json'];

        if ($this->token !== null && $this->token !== '') {
            $headers['Authorization'] = 'Bearer '.$this->token;
        }

        return $headers;
    }
}
