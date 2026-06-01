<?php

declare(strict_types=1);

namespace App\Services;

use App\Enums\Ecosystem;
use App\Support\Package;
use App\Support\Version;
use RuntimeException;
use Symfony\Component\Yaml\Yaml;

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
            $this->collectNpmV1($data['dependencies'], $packages, direct: true);

            return array_values($packages);
        }

        return [];
    }

    /**
     * @param  array<array-key, mixed>  $packagesMap
     * @return list<Package>
     */
    private function readNpmPackagesMap(array $packagesMap): array
    {
        // Direct dependencies are those declared on the root "" entry.
        $direct = [];
        $root = $packagesMap[''] ?? null;

        if (is_array($root)) {
            foreach (['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as $group) {
                foreach (array_keys((array) ($root[$group] ?? [])) as $name) {
                    $direct[(string) $name] = true;
                }
            }
        }

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
                source: 'npm',
                isDirect: isset($direct[$name]),
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
     * @param  array<array-key, mixed>  $dependencies
     * @param  array<string, Package>  $packages
     */
    private function collectNpmV1(array $dependencies, array &$packages, bool $direct): void
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
                    source: 'npm',
                    isDirect: $direct,
                );
            }

            if (isset($entry['dependencies']) && is_array($entry['dependencies'])) {
                $this->collectNpmV1($entry['dependencies'], $packages, direct: false);
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
            source: 'composer',
        );
    }

    /**
     * Read a pnpm-lock.yaml (lockfileVersion 5.x / 6.0 / 9.0). All entries
     * resolve to the npm ecosystem; the manager label is "pnpm".
     *
     * @return list<Package>
     *
     * @throws RuntimeException on a missing file or invalid YAML.
     */
    public function readPnpm(string $path): array
    {
        if (! is_file($path)) {
            throw new RuntimeException("Lockfile not found: {$path}");
        }

        try {
            $data = Yaml::parseFile($path);
        } catch (\Throwable $e) {
            throw new RuntimeException("Invalid YAML in lockfile: {$path}");
        }

        if (! is_array($data)) {
            throw new RuntimeException("Invalid pnpm lockfile: {$path}");
        }

        $lockVersion = (string) ($data['lockfileVersion'] ?? '');
        $isV5 = str_starts_with($lockVersion, '5');

        [$devDirect, $prodDirect] = $this->pnpmDirectDeps($data);

        $packages = [];

        foreach (($data['packages'] ?? []) as $key => $meta) {
            if (! is_string($key)) {
                continue;
            }

            [$name, $version] = $this->parsePnpmKey($key, $isV5);

            if ($name === '' || $version === '') {
                continue;
            }

            $dev = false;

            if (is_array($meta) && array_key_exists('dev', $meta)) {
                $dev = $meta['dev'] === true;
            } elseif (isset($devDirect[$name]) && ! isset($prodDirect[$name])) {
                $dev = true;
            }

            $packages[] = new Package(
                name: $name,
                current: Version::normalize($version),
                ecosystem: Ecosystem::Npm,
                isDev: $dev,
                source: 'pnpm',
                isDirect: isset($devDirect[$name]) || isset($prodDirect[$name]),
            );
        }

        return $packages;
    }

    /**
     * Read a bun.lock (text lockfile, JSONC). bun.lockb (binary) is rejected
     * with a hint. All entries resolve to the npm ecosystem; label "bun".
     *
     * @return list<Package>
     *
     * @throws RuntimeException on a missing/binary file or invalid JSON.
     */
    public function readBun(string $path): array
    {
        if (! is_file($path)) {
            throw new RuntimeException("Lockfile not found: {$path}");
        }

        $raw = file_get_contents($path);

        if ($raw === false) {
            throw new RuntimeException("Could not read lockfile: {$path}");
        }

        if (str_starts_with($raw, "\x00") || ! str_contains($raw, '{')) {
            throw new RuntimeException('Binary bun.lockb is not supported. Generate a text lockfile with `bun install --save-text-lockfile` (produces bun.lock).');
        }

        $data = json_decode($this->stripJsonc($raw), true);

        if (! is_array($data)) {
            throw new RuntimeException("Invalid JSON in lockfile: {$path}");
        }

        [$devDirect, $prodDirect] = $this->bunDirectDeps($data);

        $packages = [];

        foreach (($data['packages'] ?? []) as $entry) {
            $resolution = is_array($entry) ? ($entry[0] ?? null) : (is_string($entry) ? $entry : null);

            if (! is_string($resolution)) {
                continue;
            }

            [$name, $version] = $this->parseNameAtVersion($resolution);

            if ($name === '' || $version === '' || ! $this->looksLikeVersion($version)) {
                continue;
            }

            $dev = isset($devDirect[$name]) && ! isset($prodDirect[$name]);

            $packages[] = new Package(
                name: $name,
                current: Version::normalize($version),
                ecosystem: Ecosystem::Npm,
                isDev: $dev,
                source: 'bun',
                isDirect: isset($devDirect[$name]) || isset($prodDirect[$name]),
            );
        }

        return $packages;
    }

    /**
     * Read a yarn.lock — classic v1 (custom format) or berry v2+ (YAML).
     * All entries resolve to the npm ecosystem; the manager label is "yarn".
     *
     * yarn.lock records no dev/prod split, so dev flags are inferred from a
     * sibling package.json when present (direct devDependencies only).
     *
     * @return list<Package>
     *
     * @throws RuntimeException on a missing file or invalid content.
     */
    public function readYarn(string $path): array
    {
        if (! is_file($path)) {
            throw new RuntimeException("Lockfile not found: {$path}");
        }

        $raw = file_get_contents($path);

        if ($raw === false) {
            throw new RuntimeException("Could not read lockfile: {$path}");
        }

        [$devDirect, $prodDirect] = $this->yarnDirectDeps($path);

        // Berry (v2+) lockfiles are YAML and carry a "__metadata" block.
        $entries = str_contains($raw, '__metadata')
            ? $this->parseYarnBerry($raw, $path)
            : $this->parseYarnClassic($raw);

        $packages = [];
        $seen = [];

        foreach ($entries as [$name, $version]) {
            if ($name === '' || $version === '' || isset($seen[$name])) {
                continue;
            }

            $seen[$name] = true;

            $packages[] = new Package(
                name: $name,
                current: Version::normalize($version),
                ecosystem: Ecosystem::Npm,
                isDev: isset($devDirect[$name]) && ! isset($prodDirect[$name]),
                source: 'yarn',
                isDirect: isset($devDirect[$name]) || isset($prodDirect[$name]),
            );
        }

        return $packages;
    }

    /**
     * Parse a classic (v1) yarn.lock. Descriptor lines sit at column 0 and end
     * with ":"; the "version" line is indented beneath them.
     *
     * @return list<array{0: string, 1: string}> [name, version] pairs
     */
    private function parseYarnClassic(string $raw): array
    {
        $entries = [];
        $names = [];

        foreach (preg_split('/\R/', $raw) ?: [] as $line) {
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            // Descriptor header: not indented, ends with ":".
            if (! str_starts_with($line, ' ') && str_ends_with(rtrim($line), ':')) {
                $header = rtrim(rtrim($line), ':');
                $names = [];

                foreach (explode(',', $header) as $descriptor) {
                    $name = $this->yarnDescriptorName(trim($descriptor));

                    if ($name !== '') {
                        $names[] = $name;
                    }
                }

                continue;
            }

            // Version line beneath the current header.
            if (preg_match('/^\s+version\s+"?([^"\s]+)"?/', $line, $m) === 1 && $names !== []) {
                foreach ($names as $name) {
                    $entries[] = [$name, $m[1]];
                }

                $names = [];
            }
        }

        return $entries;
    }

    /**
     * Parse a berry (v2+) yarn.lock via YAML. Keys are comma-joined
     * descriptors such as "lodash@npm:^4, lodash@npm:^4.17".
     *
     * @return list<array{0: string, 1: string}> [name, version] pairs
     */
    private function parseYarnBerry(string $raw, string $path): array
    {
        try {
            $data = Yaml::parse($raw);
        } catch (\Throwable $e) {
            throw new RuntimeException("Invalid YAML in lockfile: {$path}");
        }

        if (! is_array($data)) {
            return [];
        }

        $entries = [];

        foreach ($data as $key => $meta) {
            if ($key === '__metadata' || ! is_string($key) || ! is_array($meta)) {
                continue;
            }

            $version = $meta['version'] ?? null;

            if (! is_string($version) || $version === '') {
                continue;
            }

            $first = explode(',', $key)[0];
            $name = $this->yarnDescriptorName(trim($first));

            if ($name !== '') {
                $entries[] = [$name, $version];
            }
        }

        return $entries;
    }

    /**
     * Extract the package name from a yarn descriptor, dropping the range:
     * lodash@^4.17.21 → lodash, @babel/core@npm:^7 → @babel/core.
     */
    private function yarnDescriptorName(string $descriptor): string
    {
        $descriptor = trim($descriptor, "\"' ");

        $lastAt = strrpos($descriptor, '@');

        if ($lastAt === false || $lastAt === 0) {
            return $descriptor === '' ? '' : $descriptor;
        }

        return substr($descriptor, 0, $lastAt);
    }

    /**
     * Infer direct dev/prod dependency names from a sibling package.json.
     *
     * @return array{0: array<string, true>, 1: array<string, true>} [dev, prod]
     */
    private function yarnDirectDeps(string $lockPath): array
    {
        $dev = [];
        $prod = [];

        $manifest = dirname($lockPath).DIRECTORY_SEPARATOR.'package.json';

        if (! is_file($manifest)) {
            return [$dev, $prod];
        }

        $raw = file_get_contents($manifest);
        $data = $raw === false ? null : json_decode($raw, true);

        if (! is_array($data)) {
            return [$dev, $prod];
        }

        foreach (array_keys((array) ($data['dependencies'] ?? [])) as $name) {
            $prod[(string) $name] = true;
        }

        foreach (['devDependencies', 'optionalDependencies'] as $group) {
            foreach (array_keys((array) ($data[$group] ?? [])) as $name) {
                $dev[(string) $name] = true;
            }
        }

        return [$dev, $prod];
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{0: array<string, true>, 1: array<string, true>} [dev, prod] direct dependency name sets
     */
    private function pnpmDirectDeps(array $data): array
    {
        $dev = [];
        $prod = [];

        // Workspaces (and pnpm 9) nest deps under importers.<path>; single
        // projects (v5/v6) keep them at the top level.
        $scopes = isset($data['importers']) && is_array($data['importers'])
            ? $data['importers']
            : [$data];

        foreach ($scopes as $scope) {
            if (! is_array($scope)) {
                continue;
            }

            foreach (array_keys((array) ($scope['dependencies'] ?? [])) as $name) {
                $prod[(string) $name] = true;
            }

            foreach (array_keys((array) ($scope['devDependencies'] ?? [])) as $name) {
                $dev[(string) $name] = true;
            }
        }

        return [$dev, $prod];
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{0: array<string, true>, 1: array<string, true>} [dev, prod] direct dependency name sets
     */
    private function bunDirectDeps(array $data): array
    {
        $dev = [];
        $prod = [];

        foreach (($data['workspaces'] ?? []) as $workspace) {
            if (! is_array($workspace)) {
                continue;
            }

            foreach (array_keys((array) ($workspace['dependencies'] ?? [])) as $name) {
                $prod[(string) $name] = true;
            }

            foreach (['devDependencies', 'optionalDependencies'] as $group) {
                foreach (array_keys((array) ($workspace[$group] ?? [])) as $name) {
                    $dev[(string) $name] = true;
                }
            }
        }

        return [$dev, $prod];
    }

    /**
     * Parse a pnpm `packages:` key into [name, version].
     *
     * v5:    /lodash/4.17.21        /@babel/core/7.24.0
     * v6/v9: /lodash@4.17.21(peer)  @babel/core@7.24.0
     *
     * @return array{0: string, 1: string}
     */
    private function parsePnpmKey(string $key, bool $isV5): array
    {
        $key = ltrim($key, '/');

        // Drop the peer-dependency suffix, e.g. "(react@18.0.0)".
        $paren = strpos($key, '(');

        if ($paren !== false) {
            $key = substr($key, 0, $paren);
        }

        if ($isV5) {
            $lastSlash = strrpos($key, '/');

            if ($lastSlash === false) {
                return ['', ''];
            }

            return [substr($key, 0, $lastSlash), substr($key, $lastSlash + 1)];
        }

        return $this->parseNameAtVersion($key);
    }

    /**
     * Split a "name@version" string (scope-aware) into [name, version].
     *
     * @return array{0: string, 1: string}
     */
    private function parseNameAtVersion(string $value): array
    {
        $value = ltrim($value, '/');
        $lastAt = strrpos($value, '@');

        // No "@" or it only marks the scope (e.g. "@scope/pkg" with no version).
        if ($lastAt === false || $lastAt === 0) {
            return ['', ''];
        }

        return [substr($value, 0, $lastAt), substr($value, $lastAt + 1)];
    }

    /**
     * Reject non-registry references (workspace:, github:, file:, link:, …).
     */
    private function looksLikeVersion(string $version): bool
    {
        return preg_match('/^v?\d/', $version) === 1;
    }

    /**
     * Strip JSONC extensions bun.lock uses: full-line // comments and
     * trailing commas, so the result is plain JSON.
     */
    private function stripJsonc(string $raw): string
    {
        $raw = preg_replace('#^\s*//.*$#m', '', $raw) ?? $raw;
        $raw = preg_replace('#,(\s*[}\]])#', '$1', $raw) ?? $raw;

        return $raw;
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
