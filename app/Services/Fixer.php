<?php

declare(strict_types=1);

namespace App\Services;

use App\Support\AuditResult;
use App\Support\FixSuggestion;
use App\Support\Package;
use App\Support\Version;

/**
 * Computes the minimum upgrade that leaves every currently-vulnerable range
 * and renders the matching install command for the package's manager.
 */
final class Fixer
{
    public function suggest(AuditResult $result): ?FixSuggestion
    {
        $target = $this->target($result);

        if ($target === null) {
            return null;
        }

        return new FixSuggestion($result->package, $target, $this->command($result->package, $target));
    }

    /**
     * Smallest version greater than the installed one that is not hit by any
     * current advisory. Candidates are the advisories' patched versions plus
     * the latest release; null when nothing escapes all ranges.
     */
    private function target(AuditResult $result): ?string
    {
        $vulnerabilities = $result->vulnerabilitiesNow;

        if ($vulnerabilities === []) {
            return null;
        }

        $candidates = [];

        foreach ($vulnerabilities as $advisory) {
            foreach ($advisory->patchedVersions as $patched) {
                $candidates[] = Version::normalize($patched);
            }
        }

        if ($result->package->latest !== null) {
            $candidates[] = $result->package->latest;
        }

        $candidates = array_values(array_unique($candidates));
        usort($candidates, fn (string $a, string $b): int => Version::compare($a, $b));

        foreach ($candidates as $candidate) {
            if (Version::compare($candidate, $result->package->current) <= 0) {
                continue;
            }

            $escapesAll = true;

            foreach ($vulnerabilities as $advisory) {
                if ($advisory->affects($candidate)) {
                    $escapesAll = false;
                    break;
                }
            }

            if ($escapesAll) {
                return $candidate;
            }
        }

        return null;
    }

    private function command(Package $package, string $target): string
    {
        $name = $package->name;

        return match ($package->manager()) {
            'composer' => "composer require {$name}:^{$target}",
            'npm' => "npm install {$name}@{$target}",
            'pnpm' => "pnpm add {$name}@{$target}",
            'bun' => "bun add {$name}@{$target}",
            'yarn' => "yarn add {$name}@{$target}",
            default => "# upgrade {$name} to {$target}",
        };
    }
}
