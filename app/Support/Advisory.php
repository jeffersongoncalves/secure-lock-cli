<?php

declare(strict_types=1);

namespace App\Support;

use App\Enums\Severity;

final class Advisory
{
    /**
     * @param  list<string>  $vulnerableRanges
     * @param  list<string>  $patchedVersions
     */
    public function __construct(
        public readonly string $id,
        public readonly string $title,
        public readonly Severity $severity,
        public readonly array $vulnerableRanges,
        public readonly array $patchedVersions,
        public readonly ?string $cve = null,
        public readonly ?string $link = null,
    ) {}

    /**
     * True when $version satisfies any of the vulnerable ranges.
     */
    public function affects(string $version): bool
    {
        foreach ($this->vulnerableRanges as $range) {
            if (Version::satisfies($version, $range)) {
                return true;
            }
        }

        return false;
    }

    public function severityRank(): int
    {
        return $this->severity->rank();
    }

    /**
     * Prefer the CVE identifier, fall back to the GHSA id.
     */
    public function identifier(): string
    {
        return $this->cve ?? $this->id;
    }

    /**
     * @return array{id: string, cve: ?string, severity: string, title: string, ranges: list<string>, patched: list<string>, link: ?string}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'cve' => $this->cve,
            'severity' => $this->severity->value,
            'title' => $this->title,
            'ranges' => $this->vulnerableRanges,
            'patched' => $this->patchedVersions,
            'link' => $this->link,
        ];
    }
}
