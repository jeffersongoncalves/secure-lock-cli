<?php

declare(strict_types=1);

namespace App\Support;

final class FixSuggestion
{
    public function __construct(
        public readonly Package $package,
        public readonly string $target,
        public readonly string $command,
    ) {}

    /**
     * @return array{target: string, command: string}
     */
    public function toArray(): array
    {
        return [
            'target' => $this->target,
            'command' => $this->command,
        ];
    }
}
