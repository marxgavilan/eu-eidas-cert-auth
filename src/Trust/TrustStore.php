<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Trust;

use Iberfacil\EidasCertAuth\Data\ImportResult;
use Iberfacil\EidasCertAuth\Exceptions\TrustListRejected;

final class TrustStore
{
    public function __construct(public readonly string $path, private readonly int $minimumRetentionPercent = 80) {}

    /** @return array<string, string> */
    public function certificates(): array
    {
        $manifest = $this->manifest();
        $result = [];
        foreach ($manifest as $fingerprint => $metadata) {
            $pem = @file_get_contents($this->path . '/' . $fingerprint . '.pem');
            if (is_string($pem) && hash_equals($fingerprint, (string) openssl_x509_fingerprint($pem, 'sha256'))) {
                $result[$fingerprint] = $pem;
            }
        }

        return $result;
    }

    /** @return array<string, array{country: string, service: string}> */
    public function manifest(): array
    {
        $json = @file_get_contents($this->path . '/manifest.json');
        $data = is_string($json) ? json_decode($json, true) : null;

        return is_array($data) ? $data : [];
    }

    /**
     * @param array<string, array{pem: string, country: string, service: string}> $certificates
     */
    public function publish(array $certificates, bool $force = false, bool $dryRun = false): ImportResult
    {
        $old = array_keys($this->manifest());
        $new = array_keys($certificates);
        sort($old);
        sort($new);
        $added = array_values(array_diff($new, $old));
        $removed = array_values(array_diff($old, $new));
        if ($certificates === []) {
            throw new TrustListRejected('Trusted-list replacement rejected by the CA retention safeguard.');
        }
        $retentionRejected = $old !== [] && ! $force && count($new) * 100 < count($old) * $this->minimumRetentionPercent;
        if ($dryRun) {
            return new ImportResult(count($new), $added, $removed, true, $retentionRejected);
        }
        if ($retentionRejected) {
            throw new TrustListRejected('Trusted-list replacement rejected by the CA retention safeguard.');
        }
        $parent = dirname($this->path);
        $name = basename($this->path);
        if (! is_dir($parent) || ! is_writable($parent) || (file_exists($this->path) && ! is_link($this->path))) {
            throw new TrustListRejected('The store parent must be writable and its live path must be absent or a symlink.');
        }
        $generation = $parent . '/.' . $name . '.' . bin2hex(random_bytes(8));
        if (! mkdir($generation, 0700)) {
            throw new TrustListRejected('Cannot create a trusted-store generation.');
        }
        try {
            $manifest = [];
            $bundle = '';
            ksort($certificates);
            foreach ($certificates as $fingerprint => $entry) {
                if (! preg_match('/^[0-9a-f]{64}$/', $fingerprint) || ! hash_equals($fingerprint, (string) openssl_x509_fingerprint($entry['pem'], 'sha256'))) {
                    throw new TrustListRejected('Invalid CA entry.');
                }
                $this->write($generation . '/' . $fingerprint . '.pem', $entry['pem']);
                $bundle .= $entry['pem'];
                $manifest[$fingerprint] = ['country' => $entry['country'], 'service' => $entry['service']];
            }
            $this->write($generation . '/bundle.pem', $bundle);
            $this->write($generation . '/manifest.json', (string) json_encode($manifest, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));
            $link = $parent . '/.' . $name . '.next.' . bin2hex(random_bytes(6));
            if (! symlink(basename($generation), $link) || ! rename($link, $this->path)) {
                @unlink($link);
                throw new TrustListRejected('Cannot atomically switch the trusted-store symlink.');
            }
        } catch (\Throwable $exception) {
            foreach (glob($generation . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($generation);
            throw $exception;
        }

        return new ImportResult(count($new), $added, $removed, false);
    }

    private function write(string $path, string $contents): void
    {
        if (file_put_contents($path, $contents, LOCK_EX) !== strlen($contents)) {
            throw new TrustListRejected('Cannot write trusted-store generation.');
        }
        chmod($path, 0644);
    }
}
