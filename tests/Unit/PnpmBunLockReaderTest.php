<?php

use App\Enums\Ecosystem;
use App\Services\LockReader;

it('reads pnpm-lock.yaml v9 (importers + name@version keys)', function () {
    $yaml = <<<'YAML'
    lockfileVersion: '9.0'
    importers:
      .:
        dependencies:
          lodash:
            specifier: ^4.17.21
            version: 4.17.21
        devDependencies:
          eslint:
            specifier: ^8
            version: 8.0.0
    packages:
      lodash@4.17.21:
        resolution: {integrity: sha512-x}
      '@babel/core@7.24.0':
        resolution: {integrity: sha512-y}
      eslint@8.0.0:
        resolution: {integrity: sha512-z}
    YAML;

    $packages = (new LockReader)->readPnpm(writeTempLock('pnpm-lock.yaml', $yaml));
    $byName = collect($packages)->keyBy('name');

    expect($packages)->toHaveCount(3)
        ->and($byName['lodash']->current)->toBe('4.17.21')
        ->and($byName['lodash']->ecosystem)->toBe(Ecosystem::Npm)
        ->and($byName['lodash']->manager())->toBe('pnpm')
        ->and($byName['lodash']->isDev)->toBeFalse()
        ->and($byName['@babel/core']->current)->toBe('7.24.0')
        ->and($byName['eslint']->isDev)->toBeTrue();
});

it('reads pnpm-lock.yaml v6 (leading slash + peer suffix + dev flag)', function () {
    $yaml = <<<'YAML'
    lockfileVersion: '6.0'
    dependencies:
      lodash:
        specifier: ^4
        version: 4.17.21
    devDependencies:
      eslint:
        specifier: ^8
        version: 8.0.0
    packages:
      /lodash@4.17.21:
        dev: false
      /eslint@8.0.0:
        dev: true
      /@babel/core@7.24.0(supports-color@8.1.1):
        dev: true
    YAML;

    $packages = (new LockReader)->readPnpm(writeTempLock('pnpm-lock.yaml', $yaml));
    $byName = collect($packages)->keyBy('name');

    expect($packages)->toHaveCount(3)
        ->and($byName['lodash']->isDev)->toBeFalse()
        ->and($byName['eslint']->isDev)->toBeTrue()
        ->and($byName['@babel/core']->current)->toBe('7.24.0')
        ->and($byName['@babel/core']->isDev)->toBeTrue();
});

it('reads pnpm-lock.yaml v5 (slash-separated version)', function () {
    $yaml = <<<'YAML'
    lockfileVersion: 5.4
    dependencies:
      lodash: 4.17.21
    packages:
      /lodash/4.17.21:
        dev: false
      /@babel/core/7.24.0:
        dev: true
    YAML;

    $packages = (new LockReader)->readPnpm(writeTempLock('pnpm-lock.yaml', $yaml));
    $byName = collect($packages)->keyBy('name');

    expect($packages)->toHaveCount(2)
        ->and($byName['lodash']->current)->toBe('4.17.21')
        ->and($byName['@babel/core']->current)->toBe('7.24.0')
        ->and($byName['@babel/core']->isDev)->toBeTrue();
});

it('reads bun.lock text lockfile (JSONC with comments and trailing commas)', function () {
    $jsonc = <<<'JSONC'
    {
      "lockfileVersion": 1,
      // bun text lockfile
      "workspaces": {
        "": {
          "name": "demo",
          "dependencies": { "lodash": "^4.17.21" },
          "devDependencies": { "eslint": "^8.0.0" },
        },
      },
      "packages": {
        "lodash": ["lodash@4.17.21", "", {}, "sha512-x"],
        "@babel/core": ["@babel/core@7.24.0", "", {}, "sha512-y"],
        "eslint": ["eslint@8.0.0", "", {}, "sha512-z"],
      },
    }
    JSONC;

    $packages = (new LockReader)->readBun(writeTempLock('bun.lock', $jsonc));
    $byName = collect($packages)->keyBy('name');

    expect($packages)->toHaveCount(3)
        ->and($byName['lodash']->current)->toBe('4.17.21')
        ->and($byName['lodash']->manager())->toBe('bun')
        ->and($byName['lodash']->ecosystem)->toBe(Ecosystem::Npm)
        ->and($byName['lodash']->isDev)->toBeFalse()
        ->and($byName['@babel/core']->current)->toBe('7.24.0')
        ->and($byName['eslint']->isDev)->toBeTrue();
});

it('rejects the binary bun.lockb with a helpful message', function () {
    $path = writeTempLock('bun.lockb', "\x00\x01binary garbage");

    (new LockReader)->readBun($path);
})->throws(RuntimeException::class, 'Binary bun.lockb is not supported');
