<?php

declare(strict_types=1);

namespace App\Support;

final class FixSuggestion
{
    public function __construct(
        public readonly Package $package,
        public readonly string $target,
        public readonly string $command,
        public readonly bool $transitive = false,
    ) {}

    /**
     * @return array{target: string, command: string, transitive: bool}
     */
    public function toArray(): array
    {
        return [
            'target' => $this->target,
            'command' => $this->command,
            'transitive' => $this->transitive,
        ];
    }
}
