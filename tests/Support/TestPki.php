<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Support;

use OpenSSLAsymmetricKey;
use RuntimeException;

final class TestPki
{
    private int $serial = 100;

    /**
     * @param array<string, string> $subject
     * @param array{pem: string, key: OpenSSLAsymmetricKey}|null $issuer
     * @return array{pem: string, key: OpenSSLAsymmetricKey}
     */
    public function issue(array $subject, ?array $issuer = null, string $profile = 'signer', int $days = 365): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if (! $key instanceof OpenSSLAsymmetricKey) {
            throw new RuntimeException('Cannot create a test key.');
        }
        $config = tempnam(sys_get_temp_dir(), 'eidas-pki-');
        if (! is_string($config)) {
            throw new RuntimeException('Cannot create a test config.');
        }
        $text = "[req]\ndistinguished_name=dn\n[dn]\n";
        $text .= "[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n";
        $text .= "[signer]\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n";
        $text .= "[client]\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n1.3.6.1.5.5.7.1.3=DER:30:0a:30:08:06:06:04:00:8e:46:01:01\nauthorityInfoAccess=OCSP;URI:http://ocsp.example.test/response\ncrlDistributionPoints=URI:http://crl.example.test/list.crl\n";
        $text .= "[client_no_auth]\nbasicConstraints=CA:FALSE\nkeyUsage=critical,nonRepudiation\nextendedKeyUsage=emailProtection\n";
        file_put_contents($config, $text);
        try {
            $csr = openssl_csr_new($subject, $key, ['config' => $config, 'digest_alg' => 'sha256']);
            if (! $csr instanceof \OpenSSLCertificateSigningRequest) {
                throw new RuntimeException('Cannot create a test CSR.');
            }
            $cert = openssl_csr_sign($csr, $issuer['pem'] ?? null, $issuer['key'] ?? $key, $days, ['config' => $config, 'x509_extensions' => $profile, 'digest_alg' => 'sha256'], $this->serial++);
            if (! $cert instanceof \OpenSSLCertificate || ! openssl_x509_export($cert, $pem)) {
                throw new RuntimeException('Cannot issue a test certificate.');
            }

            return ['pem' => $pem, 'key' => $key];
        } finally {
            unlink($config);
        }
    }

    public static function der(string $pem): string
    {
        $base64 = preg_replace('/-----[^-]+-----|\s+/', '', $pem);
        $der = is_string($base64) ? base64_decode($base64, true) : false;

        return is_string($der) ? $der : '';
    }

    /** @param array{pem: string, key: OpenSSLAsymmetricKey} $issuer */
    public function ocspResponse(string $clientPem, array $issuer, bool $revoked = false): string
    {
        $dir = sys_get_temp_dir() . '/eidas-ocsp-test-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        openssl_pkey_export($issuer['key'], $keyPem);
        file_put_contents($dir . '/issuer.pem', $issuer['pem']);
        file_put_contents($dir . '/issuer.key', $keyPem);
        file_put_contents($dir . '/cert.pem', $clientPem);
        $details = openssl_x509_parse($clientPem);
        $serial = strtoupper((string) ($details['serialNumberHex'] ?? ''));
        $expiry = gmdate('ymdHis', time() + 86400) . 'Z';
        $revocation = gmdate('ymdHis', time() - 60) . 'Z';
        file_put_contents($dir . '/index.txt', ($revoked ? 'R' : 'V') . "\t{$expiry}\t" . ($revoked ? $revocation : '') . "\t{$serial}\tunknown\t/CN=Test Client\n");
        try {
            self::command(['openssl', 'ocsp', '-issuer', $dir . '/issuer.pem', '-cert', $dir . '/cert.pem', '-reqout', $dir . '/req.der', '-no_nonce']);
            self::command(['openssl', 'ocsp', '-index', $dir . '/index.txt', '-rsigner', $dir . '/issuer.pem', '-rkey', $dir . '/issuer.key', '-CA', $dir . '/issuer.pem', '-reqin', $dir . '/req.der', '-respout', $dir . '/resp.der', '-ndays', '1']);

            return (string) file_get_contents($dir . '/resp.der');
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }

    /** @param array{pem: string, key: OpenSSLAsymmetricKey} $issuer */
    public function crl(string $clientPem, array $issuer, bool $revoked = false): string
    {
        $dir = sys_get_temp_dir() . '/eidas-crl-test-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        openssl_pkey_export($issuer['key'], $keyPem);
        file_put_contents($dir . '/issuer.pem', $issuer['pem']);
        file_put_contents($dir . '/issuer.key', $keyPem);
        $details = openssl_x509_parse($clientPem);
        $serial = strtoupper((string) ($details['serialNumberHex'] ?? ''));
        $expiry = gmdate('ymdHis', time() + 86400) . 'Z';
        $revocation = gmdate('ymdHis', time() - 60) . 'Z';
        file_put_contents($dir . '/index.txt', ($revoked ? 'R' : 'V') . "\t{$expiry}\t" . ($revoked ? $revocation : '') . "\t{$serial}\tunknown\t/CN=Test Client\n");
        file_put_contents($dir . '/openssl.cnf', "[ca]\ndefault_ca=CA_default\n[CA_default]\ndatabase={$dir}/index.txt\ndefault_md=sha256\ndefault_crl_days=1\n");
        try {
            self::command(['openssl', 'ca', '-gencrl', '-config', $dir . '/openssl.cnf', '-keyfile', $dir . '/issuer.key', '-cert', $dir . '/issuer.pem', '-out', $dir . '/crl.pem']);

            return (string) file_get_contents($dir . '/crl.pem');
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }

    /** @param list<string> $args */
    private static function command(array $args): void
    {
        $process = proc_open($args, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (! is_resource($process)) {
            throw new RuntimeException('Cannot start OpenSSL in test.');
        }
        fclose($pipes[0]);
        stream_get_contents($pipes[1]);
        stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        if (proc_close($process) !== 0) {
            throw new RuntimeException('OpenSSL test command failed.');
        }
    }
}
