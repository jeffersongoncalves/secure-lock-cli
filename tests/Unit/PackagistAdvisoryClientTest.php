<?php

use App\Services\HttpFetcher;
use App\Services\PackagistAdvisoryClient;
use App\Support\HttpCache;
use Illuminate\Support\Facades\Http;

function packagist(): PackagistAdvisoryClient
{
    return new PackagistAdvisoryClient(new HttpFetcher(new HttpCache(sys_get_temp_dir().'/secure-lock-test', 0)));
}

it('parses Packagist advisories, splitting affectedVersions on the OR pipe', function () {
    Http::fake([
        'packagist.org/api/security-advisories*' => Http::response([
            'advisories' => [
                'guzzlehttp/guzzle' => [
                    [
                        'advisoryId' => 'PKSA-abc',
                        'title' => 'Cross-domain cookie leakage',
                        'cve' => 'CVE-2022-31042',
                        'affectedVersions' => '>=6.0.0,<6.5.8|>=7.0.0,<7.4.5',
                        'link' => 'https://example.test',
                        'severity' => 'high',
                    ],
                ],
            ],
        ]),
    ]);

    $results = packagist()->forComposerPackages(['guzzlehttp/guzzle', 'acme/clean']);

    $guzzle = $results['guzzlehttp/guzzle'];
    $advisory = $guzzle->advisories[0];

    expect($guzzle->failed)->toBeFalse()
        ->and($guzzle->advisories)->toHaveCount(1)
        ->and($advisory->cve)->toBe('CVE-2022-31042')
        ->and($advisory->vulnerableRanges)->toBe(['>=6.0.0,<6.5.8', '>=7.0.0,<7.4.5'])
        ->and($advisory->affects('6.5.0'))->toBeTrue()
        ->and($advisory->affects('7.4.0'))->toBeTrue()
        ->and($advisory->affects('7.4.5'))->toBeFalse()
        // A package with no advisories comes back empty but not failed.
        ->and($results['acme/clean']->failed)->toBeFalse()
        ->and($results['acme/clean']->advisories)->toBeEmpty();
});

it('sends every package in a single packages[] request', function () {
    Http::fake(['packagist.org/api/security-advisories*' => Http::response(['advisories' => []])]);

    packagist()->forComposerPackages(['a/b', 'c/d']);

    Http::assertSentCount(1);
    // Both package names ride in one request (bracket encoding may vary).
    Http::assertSent(fn ($request) => str_contains($request->url(), 'a%2Fb')
        && str_contains($request->url(), 'c%2Fd'));
});

it('marks every package failed when the request fails', function () {
    Http::fake(['packagist.org/api/security-advisories*' => Http::response('', 500)]);

    $results = packagist()->forComposerPackages(['a/b']);

    expect($results['a/b']->failed)->toBeTrue();
});
