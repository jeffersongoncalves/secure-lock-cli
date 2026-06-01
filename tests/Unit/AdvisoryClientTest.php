<?php

use App\Enums\Ecosystem;
use App\Enums\Severity;
use App\Services\AdvisoryClient;
use App\Services\HttpFetcher;
use App\Support\HttpCache;
use Illuminate\Support\Facades\Http;

function advisoryClient(?string $token = null): AdvisoryClient
{
    return new AdvisoryClient(new HttpFetcher(new HttpCache(sys_get_temp_dir().'/secure-lock-test', 0)), $token);
}

it('queries the GitHub API with affects containing ONLY the package name', function () {
    Http::fake([
        'api.github.com/advisories*' => Http::response([]),
    ]);

    advisoryClient()->forName('guzzlehttp/guzzle', Ecosystem::Composer);

    Http::assertSent(function ($request) {
        $query = parse_url($request->url(), PHP_URL_QUERY);
        parse_str((string) $query, $params);

        // The ecosystem must NOT be glued onto the package name.
        return ($params['affects'] ?? null) === 'guzzlehttp/guzzle'
            && ($params['ecosystem'] ?? null) === 'composer'
            && ! str_contains((string) ($params['affects'] ?? ''), 'composer:');
    });
});

it('parses advisories and filters vulnerabilities by package name', function () {
    Http::fake([
        'api.github.com/advisories*' => Http::response([
            [
                'ghsa_id' => 'GHSA-1234',
                'cve_id' => 'CVE-2022-31042',
                'summary' => 'Cookie leak',
                'severity' => 'high',
                'html_url' => 'https://github.com/advisories/GHSA-1234',
                'vulnerabilities' => [
                    [
                        'package' => ['ecosystem' => 'composer', 'name' => 'guzzlehttp/guzzle'],
                        'vulnerable_version_range' => '< 6.5.8',
                        'first_patched_version' => ['identifier' => '6.5.8'],
                    ],
                    [
                        'package' => ['ecosystem' => 'composer', 'name' => 'other/pkg'],
                        'vulnerable_version_range' => '< 99.0.0',
                        'first_patched_version' => '99.0.0',
                    ],
                ],
            ],
        ]),
    ]);

    $result = advisoryClient()->forName('guzzlehttp/guzzle', Ecosystem::Composer);
    $advisories = $result->advisories;

    expect($result->failed)->toBeFalse()
        ->and($advisories)->toHaveCount(1)
        ->and($advisories[0]->id)->toBe('GHSA-1234')
        ->and($advisories[0]->cve)->toBe('CVE-2022-31042')
        ->and($advisories[0]->severity)->toBe(Severity::High)
        ->and($advisories[0]->vulnerableRanges)->toBe(['< 6.5.8'])
        ->and($advisories[0]->patchedVersions)->toBe(['6.5.8'])
        ->and($advisories[0]->affects('6.5.0'))->toBeTrue()
        ->and($advisories[0]->affects('7.10.0'))->toBeFalse();
});

it('sends the Authorization header when a token is provided', function () {
    Http::fake(['api.github.com/advisories*' => Http::response([])]);

    advisoryClient('secret-token')->forName('acme/lib', Ecosystem::Composer);

    Http::assertSent(fn ($request) => $request->hasHeader('Authorization', 'Bearer secret-token'));
});

it('flags a rate-limited lookup as failed instead of empty', function () {
    Http::fake([
        'api.github.com/advisories*' => Http::response('', 403, ['X-RateLimit-Remaining' => '0']),
    ]);

    $result = advisoryClient()->forName('acme/lib', Ecosystem::Composer);

    expect($result->failed)->toBeTrue()
        ->and($result->advisories)->toBeEmpty()
        ->and($result->reason)->toContain('rate limit');
});

it('flags a server error as a failed lookup', function () {
    Http::fake(['api.github.com/advisories*' => Http::response('', 500)]);

    expect(advisoryClient()->forName('acme/lib', Ecosystem::Composer)->failed)->toBeTrue();
});
