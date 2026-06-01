<?php

declare(strict_types=1);

namespace App\Support;

use Closure;

/**
 * Minimal file-backed cache with a per-instance TTL, used to avoid
 * hammering the Packagist / npm / GitHub APIs across repeated runs.
 *
 * A TTL of 0 disables caching entirely (always re-fetch, never store).
 */
final class HttpCache
{
    public function __construct(
        private readonly string $directory,
        private readonly int $ttl = 3600,
    ) {}

    /**
     * Return the cached value for $key, or compute it with $callback,
     * store it (when the TTL allows) and return it.
     */
    public function remember(string $key, Closure $callback): mixed
    {
        if ($this->ttl <= 0) {
            return $callback();
        }

        $cached = $this->get($key);

        if ($cached !== null) {
            return $cached['value'];
        }

        $value = $callback();

        $this->put($key, $value);

        return $value;
    }

    /**
     * @return array{value: mixed}|null
     */
    private function get(string $key): ?array
    {
        $path = $this->pathFor($key);

        if (! is_file($path)) {
            return null;
        }

        $raw = @file_get_contents($path);

        if ($raw === false) {
            return null;
        }

        /** @var array{expires: int, value: mixed}|null $payload */
        $payload = json_decode($raw, true);

        if (! is_array($payload) || ! isset($payload['expires'])) {
            return null;
        }

        if (time() >= (int) $payload['expires']) {
            @unlink($path);

            return null;
        }

        return ['value' => $payload['value'] ?? null];
    }

    private function put(string $key, mixed $value): void
    {
        if (! is_dir($this->directory)) {
            @mkdir($this->directory, 0755, true);
        }

        $payload = json_encode([
            'expires' => time() + $this->ttl,
            'value' => $value,
        ]);

        if ($payload === false) {
            return;
        }

        @file_put_contents($this->pathFor($key), $payload);
    }

    private function pathFor(string $key): string
    {
        return rtrim($this->directory, '/\\').DIRECTORY_SEPARATOR.'sl_'.md5($key).'.json';
    }
}
