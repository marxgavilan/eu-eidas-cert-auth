<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use DateTimeImmutable;
use Iberfacil\EidasCertAuth\Cache\InMemoryRevocationCache;
use Iberfacil\EidasCertAuth\Certificate\CertificateParser;
use Iberfacil\EidasCertAuth\Certificate\CertificateValidator;
use Iberfacil\EidasCertAuth\Certificate\RevocationChecker;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Tests\Support\TestPki;
use Iberfacil\EidasCertAuth\Transport\FakeTransport;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use PHPUnit\Framework\TestCase;

final class CertificateValidatorTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/eidas-validation-test-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/.trust.*') ?: [] as $generation) {
            if (is_link($generation)) {
                unlink($generation);
            } elseif (is_dir($generation)) {
                foreach (glob($generation . '/*') ?: [] as $file) {
                    unlink($file);
                }
                rmdir($generation);
            }
        }
        if (is_link($this->dir . '/trust')) {
            unlink($this->dir . '/trust');
        }
        rmdir($this->dir);
    }

    public function testChainIdentityAndVerifiedOcspForSpanishPortugueseItalianAndRepresentative(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Fictional Root CA', 'C' => 'ES'], profile: 'ca', days: 3650);
        $intermediate = $pki->issue(['CN' => 'Fictional Intermediate CA', 'C' => 'ES'], $root, 'ca', 3650);
        $store = new TrustStore($this->dir . '/trust');
        $fingerprint = hash('sha256', TestPki::der($root['pem']));
        $store->publish([$fingerprint => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'CA/QC']]);
        $transport = new FakeTransport();
        $cache = new InMemoryRevocationCache();
        $checker = new RevocationChecker($transport, $cache);
        $options = new Options(countries: ['ES', 'PT', 'IT', 'FR', 'DE']);
        $validator = new CertificateValidator(new CertificateParser(), $store, $checker, $options, intermediates: [$intermediate['pem']]);

        $subjects = [
            ['ES', 'IDCES-00000000T', null, 'natural'],
            ['PT', 'TINPT-000000000', null, 'natural'],
            ['IT', 'TINIT-ABC', null, 'natural'],
            ['FR', 'IDCFR-EXAMPLE1', null, 'natural'],
            ['DE', 'PASDE-EXAMPLE2', null, 'natural'],
            ['ES', 'IDCES-00000001R', 'VATES-B00000000', 'representative'],
        ];
        foreach ($subjects as [$country, $serial, $organizationIdentifier, $kind]) {
            $subject = ['CN' => 'Imaginary Citizen', 'GN' => 'Ari', 'SN' => 'Example', 'serialNumber' => $serial, 'C' => $country];
            if ($organizationIdentifier !== null) {
                $subject['organizationIdentifier'] = $organizationIdentifier;
                $subject['O'] = 'Imaginary Organization';
            }
            $client = $pki->issue($subject, $intermediate, 'client');
            $transport->respond('http://ocsp.example.test/response', $pki->ocspResponse($client['pem'], $intermediate));
            $result = $validator->validate($client['pem']);
            self::assertTrue($result->valid, (string) $result->reason);
            self::assertNotNull($result->identity);
            self::assertSame($kind, $result->identity->personType);
            self::assertSame($country, $result->identity->country);
        }
    }

    public function testRejectsRevokedExpiredNonAuthAndUntrustedCertificates(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Fictional Root CA'], profile: 'ca', days: 3650);
        $store = new TrustStore($this->dir . '/trust');
        $fingerprint = hash('sha256', TestPki::der($root['pem']));
        $store->publish([$fingerprint => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'CA/QC']]);
        $transport = new FakeTransport();
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options());
        $subject = ['CN' => 'Imaginary Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'];
        $client = $pki->issue($subject, $root, 'client');
        $transport->respond('http://ocsp.example.test/response', $pki->ocspResponse($client['pem'], $root, true));
        self::assertSame('revoked', $validator->validate($client['pem'])->reason);
        self::assertSame('expired', $validator->validate($client['pem'], new DateTimeImmutable('+2 years'))->reason);
        $expired = $pki->issue($subject, $root, 'client', 0);
        self::assertSame('expired', $validator->validate($expired['pem'], new DateTimeImmutable('+1 minute'))->reason);
        self::assertSame('not_for_authentication', $validator->validate($pki->issue($subject, $root, 'client_no_auth')['pem'])->reason);
        self::assertSame('untrusted', $validator->validate($pki->issue($subject, null, 'client')['pem'])->reason);
    }

    public function testFallsBackToSignedCrlAndCachesVerifiedStatus(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Fictional CRL CA'], profile: 'ca');
        $store = new TrustStore($this->dir . '/trust');
        $fingerprint = hash('sha256', TestPki::der($root['pem']));
        $store->publish([$fingerprint => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'CA/QC']]);
        $client = $pki->issue(['CN' => 'Example Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $root, 'client');
        $transport = (new FakeTransport())->respond('http://ocsp.example.test/response', 'unavailable')->respond('http://crl.example.test/list.crl', $pki->crl($client['pem'], $root));
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options());
        $first = $validator->validate($client['pem']);
        self::assertTrue($first->valid, (string) $first->reason);
        self::assertSame('crl', $first->revocationSource);
        $second = $validator->validate($client['pem']);
        self::assertSame('cache:crl', $second->revocationSource);
        self::assertCount(2, $transport->sent);
    }
}
