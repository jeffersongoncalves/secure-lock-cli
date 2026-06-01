<?php

declare(strict_types=1);

namespace App\Support;

/**
 * A set of advisory identifiers (GHSA or CVE) to suppress, so an accepted or
 * un-patchable risk does not keep failing CI. Entries may carry an expiry
 * date — once past, the advisory re-surfaces.
 */
final class IgnoreList
{
    /**
     * @param  array<string, true>  $ids  uppercased active identifiers
     */
    private function __construct(
        private readonly array $ids,
    ) {}

    public static function empty(): self
    {
        return new self([]);
    }

    /**
     * Build from raw entries. Each entry is either a string identifier or an
     * array {id, expires?}. `today` (Y-m-d) is used to drop expired entries.
     *
     * @param  array<int, mixed>  $entries
     */
    public static function fromEntries(array $entries, string $today): self
    {
        $ids = [];

        foreach ($entries as $entry) {
            $id = null;
            $expires = null;

            if (is_string($entry)) {
                $id = $entry;
            } elseif (is_array($entry)) {
                $id = $entry['id'] ?? null;
                $expires = $entry['expires'] ?? null;
            }

            if (! is_string($id) || $id === '') {
                continue;
            }

            // Skip expired suppressions (expires < today) so they re-surface.
            if (is_string($expires) && $expires !== '' && $expires < $today) {
                continue;
            }

            $ids[strtoupper(trim($id))] = true;
        }

        return new self($ids);
    }

    public function isEmpty(): bool
    {
        return $this->ids === [];
    }

    /**
     * True when this advisory's GHSA id or CVE is suppressed.
     */
    public function matches(Advisory $advisory): bool
    {
        if (isset($this->ids[strtoupper($advisory->id)])) {
            return true;
        }

        return $advisory->cve !== null && isset($this->ids[strtoupper($advisory->cve)]);
    }
}
