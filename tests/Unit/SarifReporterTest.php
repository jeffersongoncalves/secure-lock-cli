<?php

use App\Enums\Ecosystem;
use App\Enums\Severity;
use App\Enums\Verdict;
use App\Services\SarifReporter;
use App\Support\Advisory;
use App\Support\AuditResult;
use App\Support\Package;

it('builds SARIF 2.1.0 with a rule and result per vulnerable package', function () {
    $package = new Package('guzzlehttp/guzzle', '6.5.0', Ecosystem::Composer, source: 'composer');
    $advisory = new Advisory('GHSA-1234', 'Cookie leak', Severity::Critical, ['< 6.5.8'], ['6.5.8'], 'CVE-2022-31042', 'https://example.test');
    $result = new AuditResult($package, Verdict::SafeUpdate, [$advisory], []);

    $sarif = (new SarifReporter)->build([$result], '1.3.0');

    expect($sarif['version'])->toBe('2.1.0')
        ->and($sarif['runs'][0]['tool']['driver']['name'])->toBe('secure-lock')
        ->and($sarif['runs'][0]['tool']['driver']['version'])->toBe('1.3.0');

    $rule = $sarif['runs'][0]['tool']['driver']['rules'][0];
    $sarifResult = $sarif['runs'][0]['results'][0];

    expect($rule['id'])->toBe('CVE-2022-31042')
        ->and($rule['properties']['security-severity'])->toBe('9.0')
        ->and($sarifResult['ruleId'])->toBe('CVE-2022-31042')
        ->and($sarifResult['level'])->toBe('error')
        ->and($sarifResult['locations'][0]['physicalLocation']['artifactLocation']['uri'])->toBe('composer.lock')
        ->and($sarifResult['message']['text'])->toContain('guzzlehttp/guzzle');
});

it('emits no results when nothing is currently vulnerable', function () {
    $package = new Package('acme/lib', '1.0.0', Ecosystem::Composer, source: 'composer');
    $result = new AuditResult($package, Verdict::Ok, [], []);

    $sarif = (new SarifReporter)->build([$result], '1.3.0');

    expect($sarif['runs'][0]['results'])->toBeEmpty()
        ->and($sarif['runs'][0]['tool']['driver']['rules'])->toBeEmpty();
});
