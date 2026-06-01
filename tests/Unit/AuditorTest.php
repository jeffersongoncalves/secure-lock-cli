<?php

use App\Enums\Ecosystem;
use App\Enums\Severity;
use App\Enums\Verdict;
use App\Services\AdvisoryClient;
use App\Services\Auditor;
use App\Services\HttpFetcher;
use App\Services\RegistryClient;
use App\Support\Advisory;
use App\Support\HttpCache;
use App\Support\Package;

function makeAuditor(): Auditor
{
    // classify() never touches the clients; real instances (no network) suffice.
    $fetcher = new HttpFetcher(new HttpCache(sys_get_temp_dir().'/secure-lock-test', 0));

    return new Auditor(new RegistryClient($fetcher), new AdvisoryClient($fetcher), $fetcher);
}

function guzzleAdvisory(): Advisory
{
    return new Advisory(
        id: 'GHSA-xxxx',
        title: 'Cross-domain cookie leakage',
        severity: Severity::High,
        vulnerableRanges: ['< 6.5.8'],
        patchedVersions: ['6.5.8'],
        cve: 'CVE-2022-31042',
        link: 'https://github.com/advisories/GHSA-xxxx',
    );
}

it('classifies a vulnerable package with a fix as SAFE_UPDATE', function () {
    $package = new Package('guzzlehttp/guzzle', '6.5.0', Ecosystem::Composer);
    $package->latest = '7.10.0';
    $package->advisories = [guzzleAdvisory()];

    $result = makeAuditor()->classify($package);

    expect($result->verdict)->toBe(Verdict::SafeUpdate)
        ->and($result->vulnerabilitiesNow)->toHaveCount(1)
        ->and($result->vulnerabilitiesInLatest)->toBeEmpty();
});

it('classifies an already patched package as OK', function () {
    $package = new Package('guzzlehttp/guzzle', '7.10.0', Ecosystem::Composer);
    $package->latest = '7.10.0';
    $package->advisories = [guzzleAdvisory()];

    expect(makeAuditor()->classify($package)->verdict)->toBe(Verdict::Ok);
});

it('classifies a vulnerable package with no fix as VULN', function () {
    $package = new Package('acme/lib', '1.0.0', Ecosystem::Composer);
    $package->latest = '1.0.0';
    $package->advisories = [new Advisory('GHSA-y', 'Bad', Severity::Critical, ['<= 1.0.0'], [])];

    expect(makeAuditor()->classify($package)->verdict)->toBe(Verdict::Vuln);
});

it('classifies an update that stays vulnerable as RISKY_UPDATE', function () {
    $package = new Package('acme/lib', '1.0.0', Ecosystem::Composer);
    $package->latest = '1.5.0';
    $package->advisories = [new Advisory('GHSA-z', 'Bad', Severity::Critical, ['< 2.0.0'], ['2.0.0'])];

    expect(makeAuditor()->classify($package)->verdict)->toBe(Verdict::RiskyUpdate);
});

it('classifies a clean package with a newer version as UPDATE', function () {
    $package = new Package('acme/lib', '1.0.0', Ecosystem::Composer);
    $package->latest = '1.5.0';
    $package->advisories = [];

    expect(makeAuditor()->classify($package)->verdict)->toBe(Verdict::Update);
});

it('classifies a failed advisory lookup as UNKNOWN, never OK', function () {
    $package = new Package('acme/lib', '1.0.0', Ecosystem::Composer);
    $package->latest = '1.0.0';
    $package->advisories = [];
    $package->advisoriesFailed = true;

    $result = makeAuditor()->classify($package);

    expect($result->verdict)->toBe(Verdict::Unknown)
        ->and($result->unverified)->toBeTrue();
});
