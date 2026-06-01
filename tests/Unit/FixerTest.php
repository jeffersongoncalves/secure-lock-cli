<?php

use App\Enums\Ecosystem;
use App\Enums\Severity;
use App\Services\AdvisoryClient;
use App\Services\Auditor;
use App\Services\Fixer;
use App\Services\HttpFetcher;
use App\Services\RegistryClient;
use App\Support\Advisory;
use App\Support\AuditResult;
use App\Support\HttpCache;
use App\Support\Package;

function classify(Package $package): AuditResult
{
    $fetcher = new HttpFetcher(new HttpCache(sys_get_temp_dir().'/secure-lock-test', 0));

    return (new Auditor(
        new RegistryClient($fetcher),
        new AdvisoryClient($fetcher),
        $fetcher,
    ))->classify($package);
}

it('suggests the minimum version that escapes every vulnerable range', function () {
    $package = new Package('guzzlehttp/guzzle', '6.5.0', Ecosystem::Composer, source: 'composer');
    $package->latest = '7.10.0';
    $package->advisories = [
        new Advisory('GHSA-a', 'Bug', Severity::High, ['< 6.5.8'], ['6.5.8']),
    ];

    $suggestion = (new Fixer)->suggest(classify($package));

    expect($suggestion)->not->toBeNull()
        ->and($suggestion->target)->toBe('6.5.8')
        ->and($suggestion->command)->toBe('composer require guzzlehttp/guzzle:^6.5.8');
});

it('builds the command for the package manager', function () {
    $package = new Package('marked', '1.0.0', Ecosystem::Npm, source: 'pnpm');
    $package->latest = '4.0.0';
    $package->advisories = [
        new Advisory('GHSA-b', 'ReDoS', Severity::High, ['< 4.0.0'], ['4.0.0']),
    ];

    $suggestion = (new Fixer)->suggest(classify($package));

    expect($suggestion->target)->toBe('4.0.0')
        ->and($suggestion->command)->toBe('pnpm add marked@4.0.0');
});

it('returns null when no available version escapes the ranges', function () {
    $package = new Package('acme/lib', '1.0.0', Ecosystem::Composer, source: 'composer');
    $package->latest = '1.5.0';
    $package->advisories = [
        new Advisory('GHSA-c', 'Bad', Severity::Critical, ['< 2.0.0'], []),
    ];

    expect((new Fixer)->suggest(classify($package)))->toBeNull();
});

it('returns null for packages that are not currently vulnerable', function () {
    $package = new Package('acme/lib', '1.0.0', Ecosystem::Composer, source: 'composer');
    $package->latest = '2.0.0';
    $package->advisories = [];

    expect((new Fixer)->suggest(classify($package)))->toBeNull();
});
