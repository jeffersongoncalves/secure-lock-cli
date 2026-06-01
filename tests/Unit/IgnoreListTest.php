<?php

use App\Enums\Severity;
use App\Support\Advisory;
use App\Support\IgnoreList;

function advisory(string $id, ?string $cve = null): Advisory
{
    return new Advisory($id, 'x', Severity::High, ['< 1.0.0'], [], $cve);
}

it('matches by GHSA id and by CVE, case-insensitively', function () {
    $list = IgnoreList::fromEntries(['ghsa-aaaa', 'CVE-2022-1'], '2026-01-01');

    expect($list->matches(advisory('GHSA-AAAA')))->toBeTrue()
        ->and($list->matches(advisory('GHSA-bbbb', 'cve-2022-1')))->toBeTrue()
        ->and($list->matches(advisory('GHSA-cccc', 'CVE-9999-9')))->toBeFalse();
});

it('honors object entries and drops expired suppressions', function () {
    $list = IgnoreList::fromEntries([
        ['id' => 'GHSA-active', 'expires' => '2026-12-31'],
        ['id' => 'GHSA-expired', 'expires' => '2025-01-01'],
    ], '2026-06-01');

    expect($list->matches(advisory('GHSA-active')))->toBeTrue()
        ->and($list->matches(advisory('GHSA-expired')))->toBeFalse();
});

it('treats an empty list as suppressing nothing', function () {
    expect(IgnoreList::empty()->isEmpty())->toBeTrue()
        ->and(IgnoreList::empty()->matches(advisory('GHSA-x')))->toBeFalse();
});
