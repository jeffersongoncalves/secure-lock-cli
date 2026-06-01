<?php

declare(strict_types=1);

namespace App\Services;

use App\Enums\Ecosystem;
use App\Support\HttpCache;
use App\Support\Package;
use App\Support\Version;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Resolves the latest stable version of a package from its registry.
 */
final class RegistryClient
{
    private const PRERELEASE = '/(alpha|beta|rc|dev|next|canary|nightly)/i';

    public function __construct(
        private readonly HttpCache $cache,
        private readonly int $timeout = 15,
    ) {}

    public function latest(Package $package): ?string
    {
        return match ($package->ecosystem) {
            Ecosystem::Composer => $this->latestComposer($package->name),
            Ecosystem::Npm => $this->latestNpm($package->name),
        };
    }

    public function latestComposer(string $name): ?string
    {
        $data = $this->get("https://repo.packagist.org/p2/{$name}.json");

        if (! is_array($data)) {
            return null;
        }

        /** @var array<int, array<string, mixed>> $versions */
        $versions = $data['packages'][$name] ?? [];

        $best = null;

        foreach ($versions as $entry) {
            $version = is_array($entry) ? ($entry['version'] ?? null) : null;

            if (! is_string($version) || ! $this->isStable($version)) {
                continue;
            }

            $normalized = Version::normalize($version);

            if ($best === null || Version::greaterThan($normalized, $best)) {
                $best = $normalized;
            }
        }

        return $best;
    }

    public function latestNpm(string $name): ?string
    {
        // Encode the scope separator for scoped packages (@scope/pkg).
        $encoded = str_replace('/', '%2F', $name);

        $data = $this->get("https://registry.npmjs.org/{$encoded}");

        if (! is_array($data)) {
            return null;
        }

        $latest = $data['dist-tags']['latest'] ?? null;

        return is_string($latest) && $latest !== '' ? Version::normalize($latest) : null;
    }

    private function isStable(string $version): bool
    {
        return preg_match(self::PRERELEASE, $version) !== 1;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function get(string $url): ?array
    {
        $result = $this->cache->remember($url, function () use ($url): ?array {
            try {
                $response = Http::timeout($this->timeout)
                    ->retry(2, 200, throw: false)
                    ->acceptJson()
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
}
