<?php

declare(strict_types=1);

namespace App\Support;

/**
 * Outcome of an advisory lookup. `failed` distinguishes a genuine empty
 * result (no advisories) from a lookup that could not be completed (rate
 * limit, network error) — critical so a failed call is never mistaken for
 * "this package is clean".
 */
final class AdvisoryResult
{
    /**
     * @param  list<Advisory>  $advisories
     */
    public function __construct(
        public readonly array $advisories,
        public readonly bool $failed = false,
        public readonly ?string $reason = null,
    ) {}
}
