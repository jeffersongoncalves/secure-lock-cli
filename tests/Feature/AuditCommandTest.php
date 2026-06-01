<?php

use Illuminate\Support\Facades\Http;

function fakeGuzzleSafeUpdate(): void
{
    Http::fake([
        'repo.packagist.org/*' => Http::response([
            'packages' => [
                'guzzlehttp/guzzle' => [
                    ['version' => '7.10.0'],
                    ['version' => '6.5.0'],
                ],
            ],
        ]),
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
                ],
            ],
        ]),
    ]);
}

it('classifies a vulnerable-with-fix package as SAFE_UPDATE and exits 0', function () {
    fakeGuzzleSafeUpdate();

    $path = writeTempLock('composer.lock', json_encode([
        'packages' => [['name' => 'guzzlehttp/guzzle', 'version' => '6.5.0']],
        'packages-dev' => [],
    ]));

    $this->artisan('audit', ['--composer' => $path, '--json' => true, '--cache-ttl' => 0])
        ->expectsOutputToContain('SAFE_UPDATE')
        ->assertExitCode(0);
});

it('exits 1 when a package is vulnerable with no fix available', function () {
    Http::fake([
        'repo.packagist.org/*' => Http::response([
            'packages' => ['acme/lib' => [['version' => '1.0.0']]],
        ]),
        'api.github.com/advisories*' => Http::response([
            [
                'ghsa_id' => 'GHSA-vuln',
                'cve_id' => null,
                'summary' => 'No fix',
                'severity' => 'critical',
                'html_url' => 'https://github.com/advisories/GHSA-vuln',
                'vulnerabilities' => [
                    [
                        'package' => ['ecosystem' => 'composer', 'name' => 'acme/lib'],
                        'vulnerable_version_range' => '<= 1.0.0',
                        'first_patched_version' => null,
                    ],
                ],
            ],
        ]),
    ]);

    $path = writeTempLock('composer.lock', json_encode([
        'packages' => [['name' => 'acme/lib', 'version' => '1.0.0']],
    ]));

    $this->artisan('audit', ['--composer' => $path, '--cache-ttl' => 0])
        ->assertExitCode(1);
});

it('audits a pnpm lockfile and reports the pnpm manager in the output', function () {
    Http::fake([
        'registry.npmjs.org/*' => Http::response(['dist-tags' => ['latest' => '4.17.21']]),
        'api.github.com/advisories*' => Http::response([]),
    ]);

    $yaml = <<<'YAML'
    lockfileVersion: '9.0'
    importers:
      .:
        dependencies:
          lodash:
            specifier: ^4.17.21
            version: 4.17.21
    packages:
      lodash@4.17.21:
        resolution: {integrity: sha512-x}
    YAML;

    $path = writeTempLock('pnpm-lock.yaml', $yaml);

    $this->artisan('audit', ['--pnpm' => $path, '--json' => true, '--cache-ttl' => 0])
        ->expectsOutputToContain('pnpm')
        ->assertExitCode(0);
});

it('prints an upgrade command with --fix for a fixable vulnerability', function () {
    fakeGuzzleSafeUpdate();

    $path = writeTempLock('composer.lock', json_encode([
        'packages' => [['name' => 'guzzlehttp/guzzle', 'version' => '6.5.0']],
    ]));

    $this->artisan('audit', ['--composer' => $path, '--fix' => true, '--cache-ttl' => 0])
        ->expectsOutputToContain('composer require guzzlehttp/guzzle')
        ->assertExitCode(0);
});

it('suppresses an advisory passed via --ignore (turning VULN into OK)', function () {
    Http::fake([
        'repo.packagist.org/*' => Http::response([
            'packages' => ['acme/lib' => [['version' => '1.0.0']]],
        ]),
        'api.github.com/advisories*' => Http::response([
            [
                'ghsa_id' => 'GHSA-vuln', 'cve_id' => null, 'summary' => 'No fix',
                'severity' => 'critical', 'html_url' => 'https://example.test',
                'vulnerabilities' => [[
                    'package' => ['ecosystem' => 'composer', 'name' => 'acme/lib'],
                    'vulnerable_version_range' => '<= 1.0.0', 'first_patched_version' => null,
                ]],
            ],
        ]),
    ]);

    $path = writeTempLock('composer.lock', json_encode([
        'packages' => [['name' => 'acme/lib', 'version' => '1.0.0']],
    ]));

    // Without --ignore this is VULN (exit 1); suppressing the GHSA makes it OK.
    $this->artisan('audit', ['--composer' => $path, '--ignore' => ['GHSA-vuln'], '--cache-ttl' => 0])
        ->assertExitCode(0);
});

it('marks a package UNVERIFIED when the advisory lookup is rate limited', function () {
    Http::fake([
        'repo.packagist.org/*' => Http::response(['packages' => ['acme/lib' => [['version' => '1.0.0']]]]),
        'api.github.com/advisories*' => Http::response('', 403, ['X-RateLimit-Remaining' => '0']),
    ]);

    $path = writeTempLock('composer.lock', json_encode([
        'packages' => [['name' => 'acme/lib', 'version' => '1.0.0']],
    ]));

    // Default: unverified does not fail CI...
    $this->artisan('audit', ['--composer' => $path, '--cache-ttl' => 0])->assertExitCode(0);

    // ...but --fail-on-unverified makes it exit 1.
    $this->artisan('audit', ['--composer' => $path, '--fail-on-unverified' => true, '--cache-ttl' => 0])
        ->assertExitCode(1);
});

it('emits SARIF output for a vulnerable package', function () {
    fakeGuzzleSafeUpdate();

    $path = writeTempLock('composer.lock', json_encode([
        'packages' => [['name' => 'guzzlehttp/guzzle', 'version' => '6.5.0']],
    ]));

    $this->artisan('audit', ['--composer' => $path, '--sarif' => true, '--cache-ttl' => 0])
        ->expectsOutputToContain('"version": "2.1.0"')
        ->assertExitCode(0);
});

it('exits 2 when no lockfile is found', function () {
    $this->artisan('audit', ['--dir' => sys_get_temp_dir().'/secure-lock-empty-'.uniqid(), '--cache-ttl' => 0])
        ->assertExitCode(2);
});
