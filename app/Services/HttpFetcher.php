<?php

declare(strict_types=1);

namespace App\Services;

use App\Support\HttpCache;
use Illuminate\Http\Client\Pool;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Cache-aware HTTP layer. Single requests go through the cache; batches reuse
 * cached entries and fire the misses concurrently with Http::pool (capped),
 * collapsing the audit's many round-trips into a few concurrent waves.
 *
 * Every call yields a uniform outcome:
 *   ['failed' => bool, 'data' => array|null, 'reason' => ?string]
 * so callers can tell a genuine empty result from a failed lookup. Failures
 * are never cached, so a transient error is retried on the next run.
 */
final class HttpFetcher
{
    public function __construct(
        private readonly HttpCache $cache,
        private readonly int $concurrency = 15,
        private readonly int $timeout = 15,
    ) {}

    /**
     * @param  array<string, string>  $headers
     * @return array{failed: bool, data: array<mixed>|null, reason: ?string}
     */
    public function fetch(string $url, array $headers = []): array
    {
        $cached = $this->cache->peek($url);

        if ($cached['hit']) {
            /** @var array{failed: bool, data: array<mixed>|null, reason: ?string} $value */
            $value = $cached['value'];

            return $value;
        }

        try {
            $response = Http::timeout($this->timeout)
                ->retry(2, 200, throw: false)
                ->withHeaders($headers)
                ->get($url);
            $outcome = $this->interpret($response);
        } catch (Throwable $e) {
            $outcome = $this->failure($e->getMessage());
        }

        $this->remember($url, $outcome);

        return $outcome;
    }

    /**
     * Resolve many requests, reusing cache and pooling the misses concurrently.
     *
     * @param  array<string, array{url: string, headers?: array<string, string>}>  $requests  keyed by caller id
     * @return array<string, array{failed: bool, data: array<mixed>|null, reason: ?string}>
     */
    public function many(array $requests): array
    {
        $outcomes = [];
        $misses = [];

        foreach ($requests as $id => $request) {
            $cached = $this->cache->peek($request['url']);

            if ($cached['hit']) {
                /** @var array{failed: bool, data: array<mixed>|null, reason: ?string} $value */
                $value = $cached['value'];
                $outcomes[$id] = $value;

                continue;
            }

            $misses[$id] = $request;
        }

        foreach (array_chunk($misses, $this->concurrency, preserve_keys: true) as $batch) {
            /** @var array<string, Response|Throwable> $responses */
            $responses = Http::pool(function (Pool $pool) use ($batch): array {
                foreach ($batch as $id => $request) {
                    $pool->as((string) $id)
                        ->timeout($this->timeout)
                        ->withHeaders($request['headers'] ?? [])
                        ->get($request['url']);
                }

                return [];
            });

            foreach ($batch as $id => $request) {
                $response = $responses[$id] ?? null;

                $outcome = $response instanceof Response
                    ? $this->interpret($response)
                    : $this->failure($response instanceof Throwable ? $response->getMessage() : 'No response');

                $this->remember($request['url'], $outcome);
                $outcomes[$id] = $outcome;
            }
        }

        return $outcomes;
    }

    /**
     * @return array{failed: bool, data: array<mixed>|null, reason: ?string}
     */
    private function interpret(Response $response): array
    {
        // Rate limit: GitHub returns 403/429 with no remaining quota.
        if (in_array($response->status(), [403, 429], true)
            && (string) $response->header('X-RateLimit-Remaining') === '0') {
            return $this->failure('rate limit exceeded');
        }

        if (! $response->successful()) {
            return $this->failure('HTTP '.$response->status());
        }

        $json = $response->json();

        return ['failed' => false, 'data' => is_array($json) ? $json : [], 'reason' => null];
    }

    /**
     * @return array{failed: bool, data: null, reason: string}
     */
    private function failure(string $reason): array
    {
        return ['failed' => true, 'data' => null, 'reason' => $reason];
    }

    /**
     * @param  array{failed: bool, data: array<mixed>|null, reason: ?string}  $outcome
     */
    private function remember(string $url, array $outcome): void
    {
        // Never cache a failed lookup — retry it on the next run.
        if ($outcome['failed'] === false) {
            $this->cache->store($url, $outcome);
        }
    }
}
