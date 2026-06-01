<?php

use App\Enums\Ecosystem;
use App\Services\LockReader;

it('reads composer packages and dev packages with normalized versions', function () {
    $path = writeTempLock('composer.lock', json_encode([
        'packages' => [
            ['name' => 'guzzlehttp/guzzle', 'version' => 'v7.10.0'],
            ['name' => 'monolog/monolog', 'version' => '3.5.0'],
        ],
        'packages-dev' => [
            ['name' => 'phpunit/phpunit', 'version' => '11.0.0'],
        ],
    ]));

    $packages = (new LockReader)->readComposer($path);

    expect($packages)->toHaveCount(3)
        ->and($packages[0]->name)->toBe('guzzlehttp/guzzle')
        ->and($packages[0]->current)->toBe('7.10.0')
        ->and($packages[0]->ecosystem)->toBe(Ecosystem::Composer)
        ->and($packages[0]->isDev)->toBeFalse()
        ->and($packages[2]->name)->toBe('phpunit/phpunit')
        ->and($packages[2]->isDev)->toBeTrue();
});

it('reads npm lockfile v3 from the packages map', function () {
    $path = writeTempLock('package-lock-v3.json', json_encode([
        'lockfileVersion' => 3,
        'packages' => [
            '' => ['name' => 'root'],
            'node_modules/lodash' => ['version' => '4.17.21'],
            'node_modules/@babel/core' => ['version' => '7.24.0', 'dev' => true],
            'node_modules/a/node_modules/b' => ['version' => '1.0.0'],
        ],
    ]));

    $packages = (new LockReader)->readNpm($path);
    $byName = collect($packages)->keyBy('name');

    expect($packages)->toHaveCount(3)
        ->and($byName['lodash']->current)->toBe('4.17.21')
        ->and($byName['@babel/core']->isDev)->toBeTrue()
        ->and($byName['@babel/core']->ecosystem)->toBe(Ecosystem::Npm)
        ->and($byName['b']->current)->toBe('1.0.0');
});

it('reads npm lockfile v1 from the dependencies tree', function () {
    $path = writeTempLock('package-lock-v1.json', json_encode([
        'lockfileVersion' => 1,
        'dependencies' => [
            'lodash' => ['version' => '4.17.21'],
            'eslint' => [
                'version' => '8.0.0',
                'dev' => true,
                'dependencies' => [
                    'chalk' => ['version' => '4.1.2', 'dev' => true],
                ],
            ],
        ],
    ]));

    $packages = (new LockReader)->readNpm($path);
    $byName = collect($packages)->keyBy('name');

    expect($byName)->toHaveCount(3)
        ->and($byName['lodash']->current)->toBe('4.17.21')
        ->and($byName['eslint']->isDev)->toBeTrue()
        ->and($byName['chalk']->current)->toBe('4.1.2');
});

it('throws on a missing lockfile', function () {
    (new LockReader)->readComposer(__DIR__.'/does-not-exist.lock');
})->throws(RuntimeException::class);

it('throws on invalid JSON', function () {
    $path = writeTempLock('broken.lock', '{not json');

    (new LockReader)->readComposer($path);
})->throws(RuntimeException::class);
