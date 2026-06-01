<?php

use Tests\TestCase;

uses(TestCase::class)->in('Feature', 'Unit');

/**
 * Write a fixture lockfile under tests/tmp and return its absolute path.
 */
function writeTempLock(string $name, string $contents): string
{
    $dir = __DIR__.'/tmp';

    if (! is_dir($dir)) {
        mkdir($dir, 0755, true);
    }

    $path = $dir.'/'.$name;
    file_put_contents($path, $contents);

    return $path;
}
