<?php

declare(strict_types=1);

namespace App\Support;

use App\Enums\Ecosystem;

final class Package
{
    /**
     * Latest stable version found in the registry (filled during the audit).
     */
    public ?string $latest = null;

    /**
     * Advisories known for this package (filled during the audit).
     *
     * @var list<Advisory>
     */
    public array $advisories = [];

    /**
     * True when the advisory lookup could not be completed (rate limit,
     * network error). The package's security status is then unknown rather
     * than clean.
     */
    public bool $advisoriesFailed = false;

    public function __construct(
        public readonly string $name,
        public readonly string $current,
        public readonly Ecosystem $ecosystem,
        public readonly bool $isDev = false,
        /**
         * Display label for the package manager it came from (e.g. "pnpm",
         * "bun", "npm", "composer"). Defaults to the ecosystem label. The
         * ecosystem itself stays Composer/Npm for registry & advisory lookups.
         */
        public readonly ?string $source = null,
        /**
         * Whether the project depends on this package directly (declared in
         * the manifest) vs. pulled in transitively. Drives how --fix proposes
         * the upgrade (a direct add/require vs. an overrides/resolutions edit).
         */
        public readonly bool $isDirect = true,
    ) {}

    /**
     * The package manager label shown in the ECO column.
     */
    public function manager(): string
    {
        return $this->source ?? $this->ecosystem->label();
    }

    public function hasUpdate(): bool
    {
        return $this->latest !== null && Version::greaterThan($this->latest, $this->current);
    }

    /**
     * Advisories whose vulnerable range still covers the installed version.
     *
     * @return list<Advisory>
     */
    public function currentVulnerabilities(): array
    {
        return array_values(array_filter(
            $this->advisories,
            fn (Advisory $advisory): bool => $advisory->affects($this->current),
        ));
    }

    /**
     * Advisories whose vulnerable range still covers the latest version.
     * Empty (with an update available) means the update is safe.
     *
     * @return list<Advisory>
     */
    public function vulnerabilitiesInLatest(): array
    {
        if ($this->latest === null) {
            return [];
        }

        $latest = $this->latest;

        return array_values(array_filter(
            $this->advisories,
            fn (Advisory $advisory): bool => $advisory->affects($latest),
        ));
    }
}
