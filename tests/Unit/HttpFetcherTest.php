<?php

use App\Services\HttpFetcher;
use App\Support\HttpCache;
use Illuminate\Support\Facades\Http;

function fetcher(int $ttl = 0, ?string $dir = null): HttpFetcher
{
    return new HttpFetcher(new HttpCache($dir ?? sys_get_temp_dir().'/secure-lock-test', $ttl));
}

it('resolves a batch concurrently, separating success from failure', function () {
    Http::fake([
        'ok.test/*' => Http::response(['value' => 1]),
        'fail.test/*' => Http::response('', 500),
        'limit.test/*' => Http::response('', 403, ['X-RateLimit-Remaining' => '0']),
    ]);

    $out = fetcher()->many([
        'a' => ['url' => 'https://ok.test/1'],
        'b' => ['url' => 'https://fail.test/2'],
        'c' => ['url' => 'https://limit.test/3'],
    ]);

    expect($out['a']['failed'])->toBeFalse()
        ->and($out['a']['data'])->toBe(['value' => 1])
        ->and($out['b']['failed'])->toBeTrue()
        ->and($out['c']['failed'])->toBeTrue()
        ->and($out['c']['reason'])->toContain('rate limit');
});

it('serves a repeated request from cache (one HTTP call)', function () {
    Http::fake(['ok.test/*' => Http::response(['value' => 1])]);

    $dir = sys_get_temp_dir().'/secure-lock-fetch-'.uniqid();
    $fetcher = fetcher(3600, $dir);

    $fetcher->fetch('https://ok.test/x');
    $second = $fetcher->fetch('https://ok.test/x');

    expect($second['data'])->toBe(['value' => 1]);
    Http::assertSentCount(1);
});

it('does not cache a failed lookup (so it is retried next run)', function () {
    Http::fake(['fail.test/*' => Http::response('', 500)]);

    $dir = sys_get_temp_dir().'/secure-lock-fetch-'.uniqid();

    $outcome = fetcher(3600, $dir)->fetch('https://fail.test/x');

    expect($outcome['failed'])->toBeTrue()
        // The failure must not have been written to the cache.
        ->and((new HttpCache($dir, 3600))->peek('https://fail.test/x')['hit'])->toBeFalse();
});
