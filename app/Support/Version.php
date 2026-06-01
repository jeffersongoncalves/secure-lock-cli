<?php

declare(strict_types=1);

namespace App\Support;

use Composer\Semver\Comparator;
use Composer\Semver\Semver;
use Throwable;

/**
 * Thin semver helper around composer/semver that also understands the
 * range dialect used by the GitHub Advisory Database (comma = AND,
 * spaces between operator and version, leading "v", build metadata).
 */
final class Version
{
    /**
     * Strip a leading "v"/"V" and build metadata ("+...").
     */
    public static function normalize(string $version): string
    {
        $version = ltrim(trim($version), 'vV');

        $plus = strpos($version, '+');

        if ($plus !== false) {
            $version = substr($version, 0, $plus);
        }

        return $version;
    }

    /**
     * -1 if a < b, 0 if equal, 1 if a > b.
     */
    public static function compare(string $a, string $b): int
    {
        $a = self::normalize($a);
        $b = self::normalize($b);

        try {
            if (Comparator::equalTo($a, $b)) {
                return 0;
            }

            return Comparator::lessThan($a, $b) ? -1 : 1;
        } catch (Throwable) {
            return version_compare($a, $b);
        }
    }

    public static function greaterThan(string $a, string $b): bool
    {
        return self::compare($a, $b) > 0;
    }

    /**
     * Does $version fall inside $range? Accepts GitHub Advisory ranges
     * such as "< 6.5.8" or ">= 7.0.0, < 7.4.5" (comma = logical AND).
     */
    public static function satisfies(string $version, string $range): bool
    {
        $constraint = self::normalizeConstraint($range);

        if ($constraint === '') {
            return false;
        }

        try {
            return Semver::satisfies(self::normalize($version), $constraint);
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Turn a GHSA range into a composer/semver constraint:
     * comma -> AND (space), and operators glued to their operand.
     */
    public static function normalizeConstraint(string $range): string
    {
        $range = trim($range);

        if ($range === '') {
            return '';
        }

        // GHSA uses comma for logical AND; composer/semver uses whitespace.
        $range = str_replace(',', ' ', $range);

        // Glue operators to their version: ">= 7.0.0" -> ">=7.0.0".
        $range = preg_replace('/(>=|<=|!=|>|<|=)\s+/', '$1', $range) ?? $range;

        // Collapse remaining whitespace.
        $range = preg_replace('/\s+/', ' ', $range) ?? $range;

        return trim($range);
    }
}
