<?php

declare(strict_types=1);

namespace App\Enums;

enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Moderate = 'moderate';
    case Low = 'low';
    case Unknown = 'unknown';

    /**
     * Build from the raw GitHub Advisory severity string, normalizing
     * the "medium" alias to "moderate" and unknown values to Unknown.
     */
    public static function fromGitHub(?string $value): self
    {
        $normalized = strtolower(trim((string) $value));

        if ($normalized === 'medium') {
            $normalized = 'moderate';
        }

        return self::tryFrom($normalized) ?? self::Unknown;
    }

    public function rank(): int
    {
        return match ($this) {
            self::Critical => 4,
            self::High => 3,
            self::Moderate => 2,
            self::Low => 1,
            self::Unknown => 0,
        };
    }
}
