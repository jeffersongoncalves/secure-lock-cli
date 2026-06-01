<?php

declare(strict_types=1);

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Phar;
use RuntimeException;
use Throwable;

final class SelfUpdateService
{
    private const GITHUB_REPO = 'jeffersongoncalves/secure-lock-cli';

    private const ASSET_NAME = 'secure-lock.phar';

    public function getCurrentVersion(): string
    {
        return config('app.version', 'unreleased');
    }

    public function isRunningAsPhar(): bool
    {
        return Phar::running(false) !== '';
    }

    /**
     * @return array{tag: string, url: string}
     *
     * @throws RuntimeException
     */
    public function getLatestRelease(): array
    {
        try {
            $response = Http::acceptJson()
                ->retry(2, 200, throw: false)
                ->get('https://api.github.com/repos/'.self::GITHUB_REPO.'/releases/latest');
        } catch (Throwable $e) {
            throw new RuntimeException('Failed to fetch latest release from GitHub: '.$e->getMessage());
        }

        if (! $response->successful()) {
            throw new RuntimeException('Failed to fetch latest release from GitHub.');
        }

        $data = $response->json();
        $tag = is_array($data) ? ($data['tag_name'] ?? null) : null;

        if (! is_string($tag) || $tag === '') {
            throw new RuntimeException('Invalid release data from GitHub.');
        }

        $downloadUrl = null;

        foreach ($data['assets'] ?? [] as $asset) {
            if (is_array($asset) && ($asset['name'] ?? null) === self::ASSET_NAME) {
                $downloadUrl = $asset['browser_download_url'] ?? null;
                break;
            }
        }

        if (! is_string($downloadUrl) || $downloadUrl === '') {
            throw new RuntimeException('PHAR asset not found in the latest release.');
        }

        return ['tag' => $tag, 'url' => $downloadUrl];
    }

    public function isUpdateAvailable(string $currentVersion, string $latestTag): bool
    {
        $current = ltrim($currentVersion, 'v');
        $latest = ltrim($latestTag, 'v');

        if ($current === 'unreleased') {
            return true;
        }

        return version_compare($current, $latest, '<');
    }

    /**
     * @throws RuntimeException
     */
    public function download(string $url): string
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'secure_lock_');

        if ($tempFile === false) {
            throw new RuntimeException('Failed to create temporary file.');
        }

        try {
            Http::sink($tempFile)->get($url);
        } catch (Throwable $e) {
            @unlink($tempFile);

            throw new RuntimeException('Failed to download the PHAR file: '.$e->getMessage());
        }

        if (! $this->isValidPhar($tempFile)) {
            @unlink($tempFile);

            throw new RuntimeException('Downloaded file is not a valid PHAR.');
        }

        return $tempFile;
    }

    /**
     * @throws RuntimeException
     */
    public function replacePhar(string $tempFile): void
    {
        $pharPath = Phar::running(false);

        if ($pharPath === '') {
            @unlink($tempFile);

            throw new RuntimeException('Cannot determine current PHAR path.');
        }

        $backupPath = $pharPath.'.backup';

        if (! @copy($pharPath, $backupPath)) {
            @unlink($tempFile);

            throw new RuntimeException('Failed to create backup of current PHAR.');
        }

        $replaced = @rename($tempFile, $pharPath) || @copy($tempFile, $pharPath);

        if (! $replaced) {
            @rename($backupPath, $pharPath);
            @unlink($tempFile);

            throw new RuntimeException('Failed to replace PHAR file.');
        }

        @chmod($pharPath, 0755);
        @unlink($backupPath);
        @unlink($tempFile);
    }

    private function isValidPhar(string $path): bool
    {
        $fileSize = @filesize($path);

        if ($fileSize === false || $fileSize < 100) {
            return false;
        }

        $header = @file_get_contents($path, false, null, 0, 50);

        if ($header === false) {
            return false;
        }

        return str_contains($header, '<?php') || str_contains($header, '#!/');
    }
}
