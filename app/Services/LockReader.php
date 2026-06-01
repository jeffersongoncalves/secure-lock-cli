<?php

declare(strict_types=1);

namespace App\Services;

use App\Enums\Ecosystem;
use App\Support\Package;
use App\Support\Version;
use RuntimeException;

/**
 * Reads installed packages out of composer.lock and package-lock.json.
 */
final class LockReader
{
    /**
     * @return list<Package>
     *
     * @throws RuntimeException on a missing file or invalid JSON.
     */
    public function readComposer(string $path): array
    {
        $data = $this->decode($path);

        $packages = [];

        foreach ($data['packages'] ?? [] as $entry) {
            $package = $this->makeComposerPackage($entry, isDev: false);

            if ($package !== null) {
                $packages[] = $package;
            }
        }

        foreach ($data['packages-dev'] ?? [] as $entry) {
            $package = $this->makeComposerPackage($entry, isDev: true);

            if ($package !== null) {
                $packages[] = $package;
            }
        }

        return $packages;
    }

    /**
     * @return list<Package>
     *
     * @throws RuntimeException on a missing file or invalid JSON.
     */
    public function readNpm(string $path): array
    {
        $data = $this->decode($path);

        // Lockfile v2/v3: the "packages" map keyed by node_modules path.
        if (isset($data['packages']) && is_array($data['packages'])) {
            return $this->readNpmPackagesMap($data['packages']);
        }

        // Lockfile v1: the "dependencies" tree.
        if (isset($data['dependencies']) && is_array($data['dependencies'])) {
            $packages = [];
            $this->collectNpmV1($data['dependencies'], $packages);

            return array_values($packages);
        }

        return [];
    }

    /**
     * @param  array<string, mixed>  $packagesMap
     * @return list<Package>
     */
    private function readNpmPackagesMap(array $packagesMap): array
    {
        $packages = [];

        foreach ($packagesMap as $key => $entry) {
            if (! is_string($key) || $key === '' || ! is_array($entry)) {
                continue;
            }

            // The root project is keyed by "" and has no node_modules prefix.
            if (! str_contains($key, 'node_modules/')) {
                continue;
            }

            $name = $this->npmNameFromPath($key);
            $version = $entry['version'] ?? null;

            if ($name === '' || ! is_string($version) || $version === '') {
                continue;
            }

            $packages[] = new Package(
                name: $name,
                current: Version::normalize($version),
                ecosystem: Ecosystem::Npm,
                isDev: ($entry['dev'] ?? false) === true,
            );
        }

        return $packages;
    }

    /**
     * The package name is the segment after the last "node_modules/",
     * preserving a leading "@scope/".
     */
    private function npmNameFromPath(string $key): string
    {
        $position = strrpos($key, 'node_modules/');

        if ($position === false) {
            return '';
        }

        return substr($key, $position + strlen('node_modules/'));
    }

    /**
     * @param  array<string, mixed>  $dependencies
     * @param  array<string, Package>  $packages
     */
    private function collectNpmV1(array $dependencies, array &$packages): void
    {
        foreach ($dependencies as $name => $entry) {
            if (! is_string($name) || ! is_array($entry)) {
                continue;
            }

            $version = $entry['version'] ?? null;

            if (is_string($version) && $version !== '' && ! isset($packages[$name])) {
                $packages[$name] = new Package(
                    name: $name,
                    current: Version::normalize($version),
                    ecosystem: Ecosystem::Npm,
                    isDev: ($entry['dev'] ?? false) === true,
                );
            }

            if (isset($entry['dependencies']) && is_array($entry['dependencies'])) {
                $this->collectNpmV1($entry['dependencies'], $packages);
            }
        }
    }

    /**
     * @param  mixed  $entry
     */
    private function makeComposerPackage($entry, bool $isDev): ?Package
    {
        if (! is_array($entry)) {
            return null;
        }

        $name = $entry['name'] ?? null;
        $version = $entry['version'] ?? null;

        if (! is_string($name) || $name === '' || ! is_string($version) || $version === '') {
            return null;
        }

        return new Package(
            name: $name,
            current: Version::normalize($version),
            ecosystem: Ecosystem::Composer,
            isDev: $isDev,
        );
    }

    /**
     * @return array<string, mixed>
     *
     * @throws RuntimeException
     */
    private function decode(string $path): array
    {
        if (! is_file($path)) {
            throw new RuntimeException("Lockfile not found: {$path}");
        }

        $raw = file_get_contents($path);

        if ($raw === false) {
            throw new RuntimeException("Could not read lockfile: {$path}");
        }

        $data = json_decode($raw, true);

        if (! is_array($data)) {
            throw new RuntimeException("Invalid JSON in lockfile: {$path}");
        }

        return $data;
    }
}
