<?php

declare(strict_types=1);

namespace App\Providers;

use App\Services\LockReader;
use Illuminate\Support\ServiceProvider;
use JeffersonGoncalves\LaravelZero\SelfUpdate\PharUpdater;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(LockReader::class);

        $this->app->singleton(PharUpdater::class, fn () => new PharUpdater(
            githubRepo: 'jeffersongoncalves/secure-lock-cli',
            assetName: 'secure-lock.phar',
            tempPrefix: 'secure_lock_',
            currentVersion: (string) config('app.version', 'unreleased'),
        ));
    }

    public function boot(): void
    {
        //
    }
}
