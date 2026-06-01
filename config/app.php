<?php

use App\Providers\AppServiceProvider;

return [
    'name' => 'Secure Lock',
    'version' => app('git.version'),
    'env' => 'development',
    'providers' => [
        AppServiceProvider::class,
    ],
];
