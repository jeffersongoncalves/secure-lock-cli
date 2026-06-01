<?php

use App\Enums\Ecosystem;
use App\Services\HttpFetcher;
use App\Services\NpmAdvisoryClient;
use App\Support\HttpCache;
use App\Support\Package;
use Illuminate\Support\Facades\Http;

function npmClient(): NpmAdvisoryClient
{
    return new NpmAdvisoryClient(new HttpFetcher(new HttpCache(sys_get_temp_dir().'/secure-lock-test', 0)));
}

function npmPackage(string $name, string $current, ?string $latest): Package
{
    $p = new Package($name, $current, Ecosystem::Npm, source: 'npm');
    $p->latest = $latest;

    return $p;
}

it('parses npm audit bulk advisories', function () {
    Http::fake([
        'registry.npmjs.org/-/npm/v1/security/advisories/bulk' => Http::response([
            'lodash' => [
                [
                    'id' => 1065,
                    'url' => 'https://github.com/advisories/GHSA-jf85-cpcp-j695',
                    'title' => 'Prototype Pollution in lodash',
                    'severity' => 'high',
                    'vulnerable_versions' => '<4.17.12',
                    'cves' => ['CVE-2019-10744'],
                ],
            ],
        ]),
    ]);

    $results = npmClient()->forPackages([
        npmPackage('lodash', '4.17.4', '4.18.1'),
        npmPackage('left-pad', '1.0.0', '1.3.0'),
    ]);

    $advisory = $results['lodash']->advisories[0];

    expect($results['lodash']->failed)->toBeFalse()
        ->and($advisory->cve)->toBe('CVE-2019-10744')
        ->and($advisory->id)->toBe('GHSA-jf85-cpcp-j695')
        ->and($advisory->vulnerableRanges)->toBe(['<4.17.12'])
        ->and($advisory->affects('4.17.4'))->toBeTrue()
        ->and($advisory->affects('4.18.1'))->toBeFalse()
        // A package with no advisories comes back empty but not failed.
        ->and($results['left-pad']->failed)->toBeFalse()
        ->and($results['left-pad']->advisories)->toBeEmpty();
});

it('posts the installed and latest versions per package', function () {
    Http::fake(['registry.npmjs.org/-/npm/v1/security/advisories/bulk' => Http::response([])]);

    npmClient()->forPackages([npmPackage('lodash', '4.17.4', '4.18.1')]);

    Http::assertSent(function ($request) {
        return $request->method() === 'POST'
            && $request['lodash'] === ['4.17.4', '4.18.1'];
    });
});

it('marks every package failed when the request fails', function () {
    Http::fake(['registry.npmjs.org/-/npm/v1/security/advisories/bulk' => Http::response('', 500)]);

    $results = npmClient()->forPackages([npmPackage('lodash', '4.17.4', '4.18.1')]);

    expect($results['lodash']->failed)->toBeTrue();
});
