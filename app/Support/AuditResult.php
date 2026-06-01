<?php

declare(strict_types=1);

namespace App\Support;

use App\Enums\Verdict;

final class AuditResult
{
    /**
     * @param  list<Advisory>  $vulnerabilitiesNow
     * @param  list<Advisory>  $vulnerabilitiesInLatest
     */
    public function __construct(
        public readonly Package $package,
        public readonly Verdict $verdict,
        public readonly array $vulnerabilitiesNow,
        public readonly array $vulnerabilitiesInLatest,
    ) {}

    /**
     * Advisories most relevant to display for this row — the ones hitting
     * the current version, or (when none) those keeping the latest exposed.
     *
     * @return list<Advisory>
     */
    public function relevantAdvisories(): array
    {
        return $this->vulnerabilitiesNow !== []
            ? $this->vulnerabilitiesNow
            : $this->vulnerabilitiesInLatest;
    }

    /**
     * The highest-severity relevant advisory, or null when there is none.
     */
    public function topAdvisory(): ?Advisory
    {
        $advisories = $this->relevantAdvisories();

        if ($advisories === []) {
            return null;
        }

        usort(
            $advisories,
            fn (Advisory $a, Advisory $b): int => $b->severityRank() <=> $a->severityRank(),
        );

        return $advisories[0];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ecosystem' => $this->package->ecosystem->value,
            'name' => $this->package->name,
            'current' => $this->package->current,
            'latest' => $this->package->latest,
            'dev' => $this->package->isDev,
            'verdict' => $this->verdict->value,
            'has_update' => $this->package->hasUpdate(),
            'vulnerabilities_now' => array_map(
                fn (Advisory $a): array => $a->toArray(),
                $this->vulnerabilitiesNow,
            ),
            'vulnerabilities_in_latest' => array_map(
                fn (Advisory $a): array => $a->toArray(),
                $this->vulnerabilitiesInLatest,
            ),
        ];
    }
}
