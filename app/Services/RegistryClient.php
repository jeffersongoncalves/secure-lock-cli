<?php

declare(strict_types=1);

namespace App\Services;

use App\Enums\Ecosystem;
use App\Support\Package;
use App\Support\Version;

/**
 * Resolves the latest stable version of a package from its registry.
 */
final class RegistryClient
{
    private const PRERELEASE = '/(alpha|beta|rc|dev|next|canary|nightly)/i';

    public function __construct(
        private readonly HttpFetcher $fetcher,
    ) {}

    public function latest(Package $package): ?string
    {
        $outcome = $this->fetcher->fetch($this->url($package), ['Accept' => 'application/json']);

        return $this->extractLatest($package, $outcome);
    }

    public function latestComposer(string $name): ?string
    {
        return $this->latest(new Package($name, '0.0.0', Ecosystem::Composer));
    }

    public function latestNpm(string $name): ?string
    {
        return $this->latest(new Package($name, '0.0.0', Ecosystem::Npm));
    }

    /**
     * The registry URL for a package (used by the batch path).
     */
    public function url(Package $package): string
    {
        return match ($package->ecosystem) {
            Ecosystem::Composer => "https://repo.packagist.org/p2/{$package->name}.json",
            // Encode the scope separator for scoped packages (@scope/pkg).
            Ecosystem::Npm => 'https://registry.npmjs.org/'.str_replace('/', '%2F', $package->name),
        };
    }

    /**
     * @param  array{failed: bool, data: array<mixed>|null, reason: ?string}  $outcome
     */
    public function extractLatest(Package $package, array $outcome): ?string
    {
        if ($outcome['failed'] || ! is_array($outcome['data'])) {
            return null;
        }

        return match ($package->ecosystem) {
            Ecosystem::Composer => $this->parseComposer($package->name, $outcome['data']),
            Ecosystem::Npm => $this->parseNpm($outcome['data']),
        };
    }

    /**
     * @param  array<mixed>  $data
     */
    private function parseComposer(string $name, array $data): ?string
    {
        $versions = $data['packages'][$name] ?? [];

        if (! is_array($versions)) {
            return null;
        }

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

    /**
     * @param  array<mixed>  $data
     */
    private function parseNpm(array $data): ?string
    {
        $latest = $data['dist-tags']['latest'] ?? null;

        return is_string($latest) && $latest !== '' ? Version::normalize($latest) : null;
    }

    private function isStable(string $version): bool
    {
        return preg_match(self::PRERELEASE, $version) !== 1;
    }
}
