<?php

declare(strict_types=1);

namespace App\Providers;

use App\Services\LockReader;
use App\Services\SelfUpdateService;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(LockReader::class);
        $this->app->singleton(SelfUpdateService::class);
    }

    public function boot(): void
    {
        //
    }
}
