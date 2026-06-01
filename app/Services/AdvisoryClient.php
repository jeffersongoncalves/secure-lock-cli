<?php

declare(strict_types=1);

namespace App\Services;

use App\Enums\Ecosystem;
use App\Enums\Severity;
use App\Support\Advisory;
use App\Support\AdvisoryResult;
use App\Support\HttpCache;
use App\Support\Package;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Fetches advisories for a package from the GitHub Advisory Database.
 */
final class AdvisoryClient
{
    private const PER_PAGE = 100;

    private const MAX_PAGES = 10;

    public function __construct(
        private readonly HttpCache $cache,
        private readonly ?string $token = null,
        private readonly int $timeout = 15,
    ) {}

    public function forPackage(Package $package): AdvisoryResult
    {
        return $this->forName($package->name, $package->ecosystem);
    }

    public function forName(string $name, Ecosystem $ecosystem): AdvisoryResult
    {
        $advisories = [];

        // Follow pagination so packages with >100 advisories are not silently
        // truncated. Stop on the first page whose lookup fails.
        for ($page = 1; $page <= self::MAX_PAGES; $page++) {
            // CRITICAL: "affects" takes ONLY the package name. Prefixing it
            // with the ecosystem (e.g. "composer:guzzlehttp/guzzle") returns
            // 200 with an empty list. The ecosystem goes in its own parameter.
            $url = 'https://api.github.com/advisories?'.http_build_query([
                'affects' => $name,
                'ecosystem' => $ecosystem->advisoryName(),
                'per_page' => self::PER_PAGE,
                'page' => $page,
            ]);

            $response = $this->get($url);

            if ($response['failed']) {
                // A failed lookup means the security status is unknown — never
                // report it as "no advisories found".
                return new AdvisoryResult($advisories, failed: true, reason: $response['reason']);
            }

            $data = $response['data'];

            if (! is_array($data) || $data === []) {
                break;
            }

            foreach ($data as $entry) {
                if (! is_array($entry)) {
                    continue;
                }

                $advisory = $this->makeAdvisory($entry, $name, $ecosystem);

                if ($advisory !== null) {
                    $advisories[] = $advisory;
                }
            }

            // Last page reached when fewer than a full page came back.
            if (count($data) < self::PER_PAGE) {
                break;
            }
        }

        return new AdvisoryResult($advisories);
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
     * @return array{failed: bool, data: array<int, mixed>|null, reason: ?string}
     */
    private function get(string $url): array
    {
        /** @var array{failed: bool, data: array<int, mixed>|null, reason: ?string} $result */
        $result = $this->cache->remember(
            $url,
            function () use ($url): array {
                try {
                    $response = Http::timeout($this->timeout)
                        ->retry(2, 200, throw: false)
                        ->withHeaders($this->headers())
                        ->get($url);
                } catch (Throwable $e) {
                    return ['failed' => true, 'data' => null, 'reason' => $e->getMessage()];
                }

                // Rate limit: GitHub returns 403/429 with no remaining quota.
                if (in_array($response->status(), [403, 429], true)
                    && (string) $response->header('X-RateLimit-Remaining') === '0') {
                    return ['failed' => true, 'data' => null, 'reason' => 'GitHub API rate limit exceeded'];
                }

                if (! $response->successful()) {
                    return ['failed' => true, 'data' => null, 'reason' => 'HTTP '.$response->status()];
                }

                $json = $response->json();

                return ['failed' => false, 'data' => is_array($json) ? $json : [], 'reason' => null];
            },
            // Never cache a failed lookup — it should be retried next run.
            fn (array $value): bool => $value['failed'] === false,
        );

        return $result;
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
