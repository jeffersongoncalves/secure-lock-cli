<?php

declare(strict_types=1);

namespace App\Enums;

enum Ecosystem: string
{
    case Composer = 'composer';
    case Npm = 'npm';

    /**
     * The ecosystem identifier used by the GitHub Advisory Database.
     */
    public function advisoryName(): string
    {
        return $this->value;
    }

    public function label(): string
    {
        return match ($this) {
            self::Composer => 'composer',
            self::Npm => 'npm',
        };
    }

    public function lockFileName(): string
    {
        return match ($this) {
            self::Composer => 'composer.lock',
            self::Npm => 'package-lock.json',
        };
    }
}
