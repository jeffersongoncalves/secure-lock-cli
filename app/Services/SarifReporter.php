<?php

declare(strict_types=1);

namespace App\Services;

use App\Support\Advisory;
use App\Support\AuditResult;

/**
 * Renders the audit as SARIF 2.1.0 so it can be uploaded to GitHub code
 * scanning and surfaced in the repository's Security tab.
 */
final class SarifReporter
{
    private const INFO_URI = 'https://github.com/jeffersongoncalves/secure-lock-cli';

    private const LOCKFILES = [
        'composer' => 'composer.lock',
        'npm' => 'package-lock.json',
        'pnpm' => 'pnpm-lock.yaml',
        'bun' => 'bun.lock',
        'yarn' => 'yarn.lock',
    ];

    /**
     * @param  list<AuditResult>  $results
     * @return array<string, mixed>
     */
    public function build(array $results, string $version): array
    {
        $rules = [];
        $sarifResults = [];

        foreach ($results as $result) {
            foreach ($result->vulnerabilitiesNow as $advisory) {
                $ruleId = $advisory->identifier();

                $rules[$ruleId] ??= $this->rule($advisory);
                $sarifResults[] = $this->result($result, $advisory, $ruleId);
            }
        }

        return [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => [
                    'driver' => [
                        'name' => 'secure-lock',
                        'informationUri' => self::INFO_URI,
                        'version' => $version,
                        'rules' => array_values($rules),
                    ],
                ],
                'results' => $sarifResults,
            ]],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function rule(Advisory $advisory): array
    {
        return [
            'id' => $advisory->identifier(),
            'name' => 'VulnerableDependency',
            'shortDescription' => ['text' => $advisory->title !== '' ? $advisory->title : $advisory->identifier()],
            'helpUri' => $advisory->link ?? self::INFO_URI,
            'properties' => [
                'security-severity' => $this->securitySeverity($advisory),
                'tags' => ['security', 'dependency'],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function result(AuditResult $result, Advisory $advisory, string $ruleId): array
    {
        $package = $result->package;
        $patched = $advisory->patchedVersions !== [] ? implode(', ', $advisory->patchedVersions) : 'none';

        $message = sprintf(
            '%s %s (%s) is affected by %s [%s]: %s. Patched in: %s.',
            $package->manager(),
            $package->name,
            $package->current,
            $ruleId,
            strtoupper($advisory->severity->value),
            $advisory->title !== '' ? $advisory->title : $ruleId,
            $patched,
        );

        return [
            'ruleId' => $ruleId,
            'level' => $this->level($advisory),
            'message' => ['text' => $message],
            'locations' => [[
                'physicalLocation' => [
                    'artifactLocation' => ['uri' => self::LOCKFILES[$package->manager()] ?? $package->manager()],
                    'region' => ['startLine' => 1],
                ],
            ]],
            'partialFingerprints' => [
                'secureLock/v1' => md5($package->manager().':'.$package->name.':'.$ruleId),
            ],
        ];
    }

    private function level(Advisory $advisory): string
    {
        return match ($advisory->severity->rank()) {
            4, 3 => 'error',   // critical, high
            2 => 'warning',    // moderate
            default => 'note',
        };
    }

    private function securitySeverity(Advisory $advisory): string
    {
        return match ($advisory->severity->rank()) {
            4 => '9.0',
            3 => '7.0',
            2 => '5.0',
            1 => '2.0',
            default => '0.0',
        };
    }
}
