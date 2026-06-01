<?php

use Tests\TestCase;

uses(TestCase::class)->in('Feature', 'Unit');

/**
 * Write a fixture lockfile under a unique tests/tmp subdirectory and return
 * its absolute path. The unique subdir keeps the parallel test runner from
 * racing on a shared basename (e.g. two tests both writing composer.lock).
 */
function writeTempLock(string $name, string $contents): string
{
    $dir = __DIR__.'/tmp/'.uniqid('lock_', true);

    if (! is_dir($dir)) {
        mkdir($dir, 0755, true);
    }

    $path = $dir.'/'.$name;
    file_put_contents($path, $contents);

    return $path;
}
