<?php

use App\Support\Version;

it('normalizes leading v and build metadata', function () {
    expect(Version::normalize('v6.5.0'))->toBe('6.5.0')
        ->and(Version::normalize('1.2.3+build.7'))->toBe('1.2.3')
        ->and(Version::normalize('7.10.5'))->toBe('7.10.5');
});

it('satisfies simple upper-bound ranges', function () {
    expect(Version::satisfies('6.5.0', '< 6.5.8'))->toBeTrue()
        ->and(Version::satisfies('7.10.5', '< 6.5.8'))->toBeFalse();
});

it('respects AND ranges where comma means logical AND', function () {
    expect(Version::satisfies('7.4.0', '>= 7.0.0, < 7.4.5'))->toBeTrue()
        ->and(Version::satisfies('7.4.5', '>= 7.0.0, < 7.4.5'))->toBeFalse()
        ->and(Version::satisfies('6.9.0', '>= 7.0.0, < 7.4.5'))->toBeFalse();
});

it('compares versions', function () {
    expect(Version::compare('7.10.0', '6.5.0'))->toBe(1)
        ->and(Version::compare('6.5.0', '7.10.0'))->toBe(-1)
        ->and(Version::compare('1.0.0', '1.0.0'))->toBe(0)
        ->and(Version::greaterThan('2.0.0', '1.9.9'))->toBeTrue();
});
