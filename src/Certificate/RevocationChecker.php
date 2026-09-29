<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Certificate;

use Iberfacil\EidasCertAuth\Contracts\RevocationCache;
use Iberfacil\EidasCertAuth\Contracts\Transport;
use Iberfacil\EidasCertAuth\Data\ParsedCertificate;
use Throwable;

final readonly class RevocationChecker
{
    public function __construct(private Transport $transport, private RevocationCache $cache, private int $timeoutSeconds = 6, private string $opensslBinary = 'openssl') {}

    /** @return array{status: string, source: string} */
    public function check(ParsedCertificate $certificate, string $issuerPem): array
    {
        $hit = $this->cache->get($certificate->fingerprint);
        if ($hit !== null) {
            return $hit;
        }
        $dir = sys_get_temp_dir() . '/eidas-revocation-' . bin2hex(random_bytes(8));
        if (! mkdir($dir, 0700)) {
            return ['status' => 'unavailable', 'source' => 'none'];
        }
        try {
            file_put_contents($dir . '/cert.pem', $certificate->pem);
            file_put_contents($dir . '/issuer.pem', $issuerPem);
            chmod($dir . '/cert.pem', 0600);
            chmod($dir . '/issuer.pem', 0600);
            $outcome = $this->ocsp($certificate, $dir) ?? $this->crl($certificate, $dir) ?? ['status' => 'unavailable', 'source' => 'none'];
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($dir);
        }
        if ($outcome['status'] !== 'unavailable') {
            $this->cache->put($certificate->fingerprint, $outcome['status'], $outcome['source'], $outcome['status'] === 'good' ? 300 : 86400);
        }

        return $outcome;
    }

    /** @return array{status: string, source: string}|null */
    private function ocsp(ParsedCertificate $certificate, string $dir): ?array
    {
        foreach ($certificate->ocspUrls as $url) {
            try {
                if ($this->run(['ocsp', '-issuer', $dir . '/issuer.pem', '-cert', $dir . '/cert.pem', '-reqout', $dir . '/req.der', '-no_nonce'])['code'] !== 0) {
                    continue;
                }
                $request = file_get_contents($dir . '/req.der');
                if (! is_string($request)) {
                    continue;
                }
                $body = $this->transport->post($url, $request, 'application/ocsp-request', $this->timeoutSeconds);
                file_put_contents($dir . '/resp.der', $body);
                $verified = $this->run(['ocsp', '-respin', $dir . '/resp.der', '-issuer', $dir . '/issuer.pem', '-cert', $dir . '/cert.pem', '-CAfile', $dir . '/issuer.pem', '-partial_chain', '-no_nonce']);
                if ($verified['code'] !== 0 || ! str_contains($verified['output'], 'Response verify OK')) {
                    continue;
                }
                if (preg_match('/cert\.pem:\s*(good|revoked)\b/', $verified['output'], $matches)) {
                    return ['status' => $matches[1], 'source' => 'ocsp'];
                }
            } catch (Throwable) {
                continue;
            }
        }

        return null;
    }

    /** @return array{status: string, source: string}|null */
    private function crl(ParsedCertificate $certificate, string $dir): ?array
    {
        foreach ($certificate->crlUrls as $url) {
            try {
                $body = $this->transport->get($url, $this->timeoutSeconds);
                file_put_contents($dir . '/crl.raw', $body);
                $format = str_contains($body, '-----BEGIN X509 CRL-----') ? 'PEM' : 'DER';
                if ($this->run(['crl', '-inform', $format, '-in', $dir . '/crl.raw', '-out', $dir . '/crl.pem'])['code'] !== 0) {
                    continue;
                }
                $verified = $this->run(['verify', '-partial_chain', '-crl_check', '-CAfile', $dir . '/issuer.pem', '-CRLfile', $dir . '/crl.pem', $dir . '/cert.pem']);
                if ($verified['code'] === 0) {
                    return ['status' => 'good', 'source' => 'crl'];
                }
                if (str_contains($verified['output'], 'certificate revoked')) {
                    return ['status' => 'revoked', 'source' => 'crl'];
                }
            } catch (Throwable) {
                continue;
            }
        }

        return null;
    }

    /**
     * @param list<string> $arguments
     * @return array{code: int, output: string}
     */
    private function run(array $arguments): array
    {
        $process = proc_open([$this->opensslBinary, ...$arguments], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (! is_resource($process)) {
            return ['code' => 1, 'output' => ''];
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $output = '';
        $deadline = microtime(true) + max(1, $this->timeoutSeconds);
        do {
            $output .= stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            $status = proc_get_status($process);
            if (! $status['running']) {
                $code = $status['exitcode'];
                break;
            }
            usleep(10_000);
        } while (microtime(true) < $deadline);
        if ($status['running']) {
            proc_terminate($process, 9);
            $code = 1;
        }
        $output .= stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        return ['code' => $code, 'output' => $output];
    }
}
