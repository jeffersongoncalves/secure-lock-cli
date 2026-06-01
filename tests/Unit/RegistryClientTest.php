<?php

use App\Services\RegistryClient;
use App\Support\HttpCache;
use Illuminate\Support\Facades\Http;

function freshCache(): HttpCache
{
    return new HttpCache(sys_get_temp_dir().'/secure-lock-test', 0);
}

it('ignores Composer pre-releases when resolving the latest stable version', function () {
    Http::fake([
        'repo.packagist.org/*' => Http::response([
            'packages' => [
                'guzzlehttp/guzzle' => [
                    ['version' => '7.10.0'],
                    ['version' => '8.0.0-beta1'],
                    ['version' => '7.9.0-RC1'],
                    ['version' => 'v6.5.0'],
                    ['version' => 'dev-main'],
                ],
            ],
        ]),
    ]);

    expect((new RegistryClient(freshCache()))->latestComposer('guzzlehttp/guzzle'))->toBe('7.10.0');
});

it('uses dist-tags.latest for npm packages', function () {
    Http::fake([
        'registry.npmjs.org/*' => Http::response([
            'dist-tags' => ['latest' => '4.17.21'],
        ]),
    ]);

    expect((new RegistryClient(freshCache()))->latestNpm('lodash'))->toBe('4.17.21');
});

it('encodes the scope separator for scoped npm packages', function () {
    Http::fake([
        'registry.npmjs.org/*' => Http::response(['dist-tags' => ['latest' => '7.24.0']]),
    ]);

    (new RegistryClient(freshCache()))->latestNpm('@babel/core');

    Http::assertSent(fn ($request) => str_contains($request->url(), '%2F'));
});
