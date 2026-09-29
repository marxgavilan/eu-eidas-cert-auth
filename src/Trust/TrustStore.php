<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Trust;

use DateTimeImmutable;
use Iberfacil\EidasCertAuth\Data\ImportResult;
use Iberfacil\EidasCertAuth\Exceptions\TrustListRejected;

final class TrustStore
{
    /** @var array<string, string> */
    private array $cachedCertificates = [];

    private ?string $cachedGeneration = null;

    public function __construct(public readonly string $path, private readonly int $minimumRetentionPercent = 80, private readonly int $maximumAgeSeconds = 2592000) {}

    /** @return array<string, string>
     *  @phpstan-impure
     */
    public function certificates(): array
    {
        $generation = realpath($this->path);
        if ($generation === false) {
            return [];
        }
        try {
            $data = $this->readManifest($generation);
        } catch (TrustListRejected) {
            return [];
        }
        $generated = strtotime((string) ($data['generated_at'] ?? ''));
        $next = strtotime((string) ($data['next_update'] ?? ''));
        if ($generated === false || $next === false || $generated > time() || $next <= time() || time() - $generated > $this->maximumAgeSeconds) {
            return [];
        }
        if ($this->cachedGeneration === $generation) {
            return $this->cachedCertificates;
        }
        $result = [];
        foreach ($data['certificates'] as $fingerprint => $metadata) {
            $pem = @file_get_contents($generation . '/' . $fingerprint . '.pem');
            if (is_string($pem) && hash_equals($fingerprint, (string) openssl_x509_fingerprint($pem, 'sha256'))) {
                $result[$fingerprint] = $pem;
            }
        }
        $this->cachedGeneration = $generation;
        $this->cachedCertificates = $result;

        return $result;
    }

    /** @return array<string, array{country: string, service: string, fore_signatures?: bool, not_qualified_criteria?: list<string>}> */
    public function manifest(): array
    {
        $generation = realpath($this->path);
        if ($generation === false) {
            return [];
        }

        return $this->readManifest($generation)['certificates'];
    }

    /**
     * @param array<string, array{pem: string, country: string, service: string, fore_signatures?: bool, not_qualified_criteria?: list<string>}> $certificates
     * @param array<string, int> $sequences
     * @param array<string, string> $issueDates
     */
    public function publish(array $certificates, bool $force = false, bool $dryRun = false, array $sequences = [], ?DateTimeImmutable $nextUpdate = null, array $issueDates = []): ImportResult
    {
        $parent = dirname($this->path);
        $name = basename($this->path);
        if (! is_dir($parent) || ! is_writable($parent) || (file_exists($this->path) && ! is_link($this->path))) {
            throw new TrustListRejected('The store parent must be writable and its live path must be absent or a symlink.');
        }
        $lock = @fopen($parent . '/.' . $name . '.lock', 'c');
        if ($lock === false || ! flock($lock, LOCK_EX)) {
            throw new TrustListRejected('Cannot lock the trusted store.');
        }
        try {
            return $this->publishLocked($certificates, $force, $dryRun, $sequences, $nextUpdate, $issueDates);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * @param array<string, array{pem: string, country: string, service: string, fore_signatures?: bool, not_qualified_criteria?: list<string>}> $certificates
     * @param array<string, int> $sequences
     * @param array<string, string> $issueDates
     */
    private function publishLocked(array $certificates, bool $force, bool $dryRun, array $sequences, ?DateTimeImmutable $nextUpdate, array $issueDates): ImportResult
    {
        if (is_link($this->path)) {
            $oldGeneration = realpath($this->path);
            if ($oldGeneration === false) {
                throw new TrustListRejected('The trusted-store symlink target is missing.');
            }
            $oldData = $this->readManifest($oldGeneration);
        } else {
            $oldData = ['certificates' => [], 'sequences' => [], 'issue_dates' => []];
        }
        foreach ($sequences as $country => $number) {
            if (isset($oldData['sequences'][$country]) && ($number < $oldData['sequences'][$country] || ($number === $oldData['sequences'][$country] && isset($issueDates[$country], $oldData['issue_dates'][$country]) && strtotime($issueDates[$country]) < strtotime($oldData['issue_dates'][$country])))) {
                throw new TrustListRejected('Trusted-list sequence rollback rejected.');
            }
        }
        $mergedSequences = $oldData['sequences'];
        foreach ($sequences as $country => $number) {
            $mergedSequences[$country] = max($mergedSequences[$country] ?? 0, $number);
        }
        $mergedIssueDates = $oldData['issue_dates'] ?? [];
        foreach ($issueDates as $country => $date) {
            if (! isset($mergedIssueDates[$country]) || strtotime($date) > strtotime($mergedIssueDates[$country])) {
                $mergedIssueDates[$country] = $date;
            }
        }
        $old = array_keys($oldData['certificates']);
        $new = array_keys($certificates);
        sort($old);
        sort($new);
        $added = array_values(array_diff($new, $old));
        $removed = array_values(array_diff($old, $new));
        if ($certificates === []) {
            throw new TrustListRejected('Trusted-list replacement rejected by the CA retention safeguard.');
        }
        $retentionRejected = false;
        $oldByCountry = [];
        $newByCountry = [];
        foreach ($oldData['certificates'] as $entry) {
            $oldByCountry[$entry['country']] = ($oldByCountry[$entry['country']] ?? 0) + 1;
        }
        foreach ($certificates as $entry) {
            $newByCountry[$entry['country']] = ($newByCountry[$entry['country']] ?? 0) + 1;
        }
        foreach ($oldByCountry as $country => $count) {
            if (($newByCountry[$country] ?? 0) * 100 < $count * $this->minimumRetentionPercent) {
                $retentionRejected = true;
            }
        }
        if ($dryRun) {
            return new ImportResult(count($new), $added, $removed, true, $retentionRejected && ! $force);
        }
        if ($retentionRejected && ! $force) {
            throw new TrustListRejected('Trusted-list replacement rejected by the CA retention safeguard.');
        }
        $parent = dirname($this->path);
        $name = basename($this->path);
        $generation = $parent . '/.' . $name . '.' . bin2hex(random_bytes(8));
        if (! mkdir($generation, 0700)) {
            throw new TrustListRejected('Cannot create a trusted-store generation.');
        }
        try {
            $entries = [];
            $bundle = '';
            ksort($certificates);
            foreach ($certificates as $fingerprint => $entry) {
                if (! preg_match('/^[0-9a-f]{64}$/', $fingerprint) || ! hash_equals($fingerprint, (string) openssl_x509_fingerprint($entry['pem'], 'sha256'))) {
                    throw new TrustListRejected('Invalid CA entry.');
                }
                $this->write($generation . '/' . $fingerprint . '.pem', $entry['pem']);
                $bundle .= $entry['pem'];
                $entries[$fingerprint] = ['country' => $entry['country'], 'service' => $entry['service'], 'fore_signatures' => $entry['fore_signatures'] ?? false, 'not_qualified_criteria' => $entry['not_qualified_criteria'] ?? []];
            }
            $this->write($generation . '/bundle.pem', $bundle);
            $manifest = ['generated_at' => gmdate('c'), 'next_update' => ($nextUpdate ?? new DateTimeImmutable('+30 days'))->format(DATE_ATOM), 'sequences' => $mergedSequences, 'issue_dates' => $mergedIssueDates, 'certificates' => $entries];
            $this->write($generation . '/manifest.json', (string) json_encode($manifest, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));
            $link = $parent . '/.' . $name . '.next.' . bin2hex(random_bytes(6));
            if (! symlink(basename($generation), $link) || ! rename($link, $this->path)) {
                @unlink($link);
                throw new TrustListRejected('Cannot atomically switch the trusted-store symlink.');
            }
            $this->cachedGeneration = null;
        } catch (\Throwable $exception) {
            foreach (glob($generation . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($generation);
            throw $exception;
        }

        return new ImportResult(count($new), $added, $removed, false);
    }

    /** @return array{generated_at?: string, next_update?: string, sequences: array<string, int>, issue_dates?: array<string, string>, certificates: array<string, array{country: string, service: string, fore_signatures?: bool, not_qualified_criteria?: list<string>}>} */
    private function readManifest(string $generation): array
    {
        $json = @file_get_contents($generation . '/manifest.json');
        $data = is_string($json) ? json_decode($json, true) : null;
        $legacy = false;
        if (is_array($data) && ! isset($data['certificates'], $data['sequences']) && $data !== [] && array_is_list($data) === false && preg_match('/^[0-9a-f]{64}$/', (string) array_key_first($data))) {
            $data = ['certificates' => $data, 'sequences' => [], 'issue_dates' => []];
            $legacy = true;
        }
        if (! is_array($data) || ! isset($data['certificates'], $data['sequences']) || ! is_array($data['certificates']) || ! is_array($data['sequences'])) {
            throw new TrustListRejected('The trusted-store manifest is missing or corrupt.');
        }
        if (! $legacy && (! is_string($data['generated_at'] ?? null) || strtotime($data['generated_at']) === false || ! is_string($data['next_update'] ?? null) || strtotime($data['next_update']) === false || ! is_array($data['issue_dates'] ?? null))) {
            throw new TrustListRejected('The trusted-store time metadata is invalid.');
        }
        foreach ($data['issue_dates'] as $country => $date) {
            if (! is_string($country) || ! is_string($date) || strtotime($date) === false) {
                throw new TrustListRejected('The trusted-store issue dates are invalid.');
            }
        }
        foreach ($data['sequences'] as $country => $number) {
            if (! is_string($country) || ! is_int($number) || $number < 0) {
                throw new TrustListRejected('The trusted-store sequence metadata is invalid.');
            }
        }
        foreach ($data['certificates'] as $fingerprint => $entry) {
            if (! is_string($fingerprint) || ! preg_match('/^[0-9a-f]{64}$/', $fingerprint) || ! is_array($entry) || ! is_string($entry['country'] ?? null) || ! is_string($entry['service'] ?? null) || (isset($entry['fore_signatures']) && ! is_bool($entry['fore_signatures'])) || ! is_array($entry['not_qualified_criteria'] ?? []) || count(array_filter($entry['not_qualified_criteria'] ?? [], 'is_string')) !== count($entry['not_qualified_criteria'] ?? [])) {
                throw new TrustListRejected('The trusted-store manifest is invalid.');
            }
        }

        return $data;
    }

    private function write(string $path, string $contents): void
    {
        if (file_put_contents($path, $contents, LOCK_EX) !== strlen($contents)) {
            throw new TrustListRejected('Cannot write trusted-store generation.');
        }
        chmod($path, 0644);
    }
}
