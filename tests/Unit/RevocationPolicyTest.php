<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use Iberfacil\EidasCertAuth\Cache\InMemoryRevocationCache;
use Iberfacil\EidasCertAuth\Certificate\CertificateParser;
use Iberfacil\EidasCertAuth\Certificate\RevocationChecker;
use Iberfacil\EidasCertAuth\Data\ParsedCertificate;
use Iberfacil\EidasCertAuth\Tests\Support\TestPki;
use Iberfacil\EidasCertAuth\Transport\FakeTransport;
use PHPUnit\Framework\TestCase;

final class RevocationPolicyTest extends TestCase
{
    public function testOcspWithoutNextUpdateUnknownAndOtherCertificateFailClosed(): void
    {
        $pki = new TestPki();
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $client = $pki->issue(['CN' => 'Citizen'], $ca, 'client');
        $other = $pki->issue(['CN' => 'Other'], $ca, 'client');
        $parsed = (new CertificateParser())->parse($client['pem']);
        self::assertInstanceOf(ParsedCertificate::class, $parsed);
        $parsed = new ParsedCertificate($parsed->pem, $parsed->fingerprint, $parsed->subject, $parsed->issuer, $parsed->notBefore, $parsed->notAfter, $parsed->keyUsage, $parsed->extendedKeyUsage, $parsed->qualified, $parsed->ocspUrls, []);
        foreach ([$pki->ocspResponse($client['pem'], $ca, noNext: true), $pki->ocspResponse($client['pem'], $ca, unknown: true), $pki->ocspResponse($other['pem'], $ca)] as $response) {
            $transport = (new FakeTransport())->respond('http://ocsp.example.test/response', $response);
            $checker = new RevocationChecker($transport, new InMemoryRevocationCache());
            self::assertSame('unavailable', $checker->check($parsed, $ca['pem'])['status']);
        }
    }

    public function testCrlFromOtherSignerCannotRevokeOrApprove(): void
    {
        $pki = new TestPki();
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $rogue = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $client = $pki->issue(['CN' => 'Citizen'], $ca, 'client');
        $parsed = (new CertificateParser())->parse($client['pem']);
        self::assertInstanceOf(ParsedCertificate::class, $parsed);
        $transport = (new FakeTransport())->respond('http://ocsp.example.test/response', 'invalid')->respond('http://crl.example.test/list.crl', $pki->crl($client['pem'], $rogue, true));
        self::assertSame('unavailable', (new RevocationChecker($transport, new InMemoryRevocationCache()))->check($parsed, $ca['pem'])['status']);
    }
    public function testOldExpiredWrongCertWrongSignerAndBadDelegationAreRejected(): void
    {
        $probe = proc_open(['python3', '-c', 'import cryptography'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $probePipes);
        if (! is_resource($probe)) {
            self::markTestSkipped('Python cryptography is unavailable.');
        }
        foreach ($probePipes as $pipe) {
            fclose($pipe);
        }
        if (proc_close($probe) !== 0) {
            self::markTestSkipped('Python cryptography is unavailable.');
        }
        $pki = new TestPki();
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca', days: 3650);
        $client = $pki->issue(['CN' => 'Citizen'], $ca, 'client');
        $other = $pki->issue(['CN' => 'Other'], $ca, 'client');
        $rogue = $pki->issue(['CN' => 'Rogue'], profile: 'ca');
        $dir = sys_get_temp_dir() . '/eidas-old-ocsp-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        file_put_contents($dir . '/issuer.pem', $ca['pem']);
        openssl_pkey_export($ca['key'], $key);
        file_put_contents($dir . '/issuer.key', $key);
        file_put_contents($dir . '/cert.pem', $client['pem']);
        foreach (['other' => $other, 'rogue' => $rogue] as $name => $issued) {
            file_put_contents($dir . '/' . $name . '.pem', $issued['pem']);
            openssl_pkey_export($issued['key'], $key);
            file_put_contents($dir . '/' . $name . '.key', $key);
        }
        try {
            foreach (['old_no_next', 'expired', 'other_cert', 'other_signer', 'delegated_no_eku'] as $case) {
                $process = proc_open(['python3', __DIR__ . '/../Support/mkocsp.py', $dir, $case], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
                self::assertIsResource($process);
                fclose($pipes[0]);
                $response = stream_get_contents($pipes[1]);
                $errors = stream_get_contents($pipes[2]);
                fclose($pipes[1]);
                fclose($pipes[2]);
                self::assertSame(0, proc_close($process), $errors);
                $parsed = (new CertificateParser())->parse($client['pem']);
                self::assertInstanceOf(ParsedCertificate::class, $parsed);
                $parsed = new ParsedCertificate($parsed->pem, $parsed->fingerprint, $parsed->subject, $parsed->issuer, $parsed->notBefore, $parsed->notAfter, $parsed->keyUsage, $parsed->extendedKeyUsage, $parsed->qualified, $parsed->ocspUrls, []);
                $transport = (new FakeTransport())->respond('http://ocsp.example.test/response', $response);
                self::assertSame('unavailable', (new RevocationChecker($transport, new InMemoryRevocationCache()))->check($parsed, $ca['pem'])['status'], $case);
            }
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }
    public function testExpiredCrlIsUnavailable(): void
    {
        $probe = proc_open(['python3', '-c', 'import cryptography'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $probePipes);
        if (! is_resource($probe)) {
            self::markTestSkipped('Python cryptography is unavailable.');
        }
        foreach ($probePipes as $pipe) {
            fclose($pipe);
        }
        if (proc_close($probe) !== 0) {
            self::markTestSkipped('Python cryptography is unavailable.');
        }
        $pki = new TestPki();
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $client = $pki->issue(['CN' => 'Citizen'], $ca, 'client');
        $parsed = (new CertificateParser())->parse($client['pem']);
        self::assertInstanceOf(ParsedCertificate::class, $parsed);
        $dir = sys_get_temp_dir() . '/eidas-expired-crl-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        file_put_contents($dir . '/issuer.pem', $ca['pem']);
        openssl_pkey_export($ca['key'], $key);
        file_put_contents($dir . '/issuer.key', $key);
        try {
            $process = proc_open(['python3', __DIR__ . '/../Support/mkcrl.py', $dir, 'expired'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            self::assertIsResource($process);
            fclose($pipes[0]);
            $crl = stream_get_contents($pipes[1]);
            $errors = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            self::assertSame(0, proc_close($process), $errors);
            $transport = (new FakeTransport())->respond('http://ocsp.example.test/response', 'invalid')->respond('http://crl.example.test/list.crl', $crl);
            self::assertSame('unavailable', (new RevocationChecker($transport, new InMemoryRevocationCache()))->check($parsed, $ca['pem'])['status']);
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }

}
