<?php

declare(strict_types=1);

namespace App\Enums;

enum Verdict: string
{
    case Vuln = 'VULN';
    case RiskyUpdate = 'RISKY_UPDATE';
    case Unknown = 'UNKNOWN';
    case SafeUpdate = 'SAFE_UPDATE';
    case Update = 'UPDATE';
    case Ok = 'OK';

    /**
     * Colored badge for the human-readable table.
     */
    public function badge(): string
    {
        return match ($this) {
            self::Vuln => '<fg=red>● VULN</>',
            self::RiskyUpdate => '<fg=magenta>● RISKY</>',
            self::Unknown => '<fg=yellow>● UNKNOWN</>',
            self::SafeUpdate => '<fg=green>● SAFE</>',
            self::Update => '<fg=cyan>● UPDATE</>',
            self::Ok => '<fg=gray>● OK</>',
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Vuln => 'vulnerable now',
            self::RiskyUpdate => 'risky update',
            self::Unknown => 'unverified',
            self::SafeUpdate => 'safe update',
            self::Update => 'update available',
            self::Ok => 'up to date',
        };
    }

    /**
     * Sort weight — higher means more urgent (rendered first).
     */
    public function riskOrder(): int
    {
        return match ($this) {
            self::Vuln => 6,
            self::RiskyUpdate => 5,
            self::Unknown => 4,
            self::SafeUpdate => 3,
            self::Update => 2,
            self::Ok => 1,
        };
    }

    /**
     * Whether this verdict should fail a CI pipeline (without extra flags).
     */
    public function failsCi(): bool
    {
        return $this === self::Vuln || $this === self::RiskyUpdate;
    }
}
