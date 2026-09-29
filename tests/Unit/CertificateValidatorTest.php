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
            if (is_link($generation) || is_file($generation)) {
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
    public function testValidationFailureReasonsAndSoftFailPolicy(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Root'], profile: 'ca', days: 3650);
        $store = new TrustStore($this->dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'CA/QC']]);
        $transport = new FakeTransport();
        $strict = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options());
        $subject = ['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'];
        $client = $pki->issue($subject, $root, 'client');
        self::assertSame('not_yet_valid', $strict->validate($client['pem'], new DateTimeImmutable('-1 day'))->reason);
        self::assertSame('revocation_unavailable', $strict->validate($client['pem'])->reason);
        $soft = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options(softFailRevocation: true));
        self::assertTrue($soft->validate($client['pem'])->valid);
        self::assertSame('not_qualified', $strict->validate($pki->issue($subject, $root, 'client_no_qc')['pem'])->reason);
        self::assertSame('not_qualified', $strict->validate($pki->issue($subject, $root, 'client_fake_qc')['pem'])->reason);
        self::assertSame('country_not_accepted', $strict->validate($pki->issue(['CN' => 'PT', 'serialNumber' => 'TINPT-123', 'C' => 'PT'], $root, 'client')['pem'])->reason);
        self::assertSame('no_personal_identity', $strict->validate($pki->issue(['CN' => 'Company', 'C' => 'ES'], $root, 'client')['pem'])->reason);
        self::assertSame('untrusted', $strict->validate($pki->issue($subject, $root, 'client', digest: 'sha1')['pem'])->reason);
        $leafIssuer = $pki->issue(['CN' => 'Leaf issuer'], $root, 'client');
        self::assertSame('untrusted', $strict->validate($pki->issue($subject, $leafIssuer, 'client')['pem'])->reason);
        $intermediate = $pki->issue(['CN' => 'Intermediate'], $root, 'ca');
        self::assertSame('untrusted', $strict->validate($pki->issue($subject, $intermediate, 'client')['pem'])->reason);
    }

    public function testRevokedCrlAndCaKeyUsageAreRejected(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Root'], profile: 'ca');
        $store = new TrustStore($this->dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'CA/QC']]);
        $client = $pki->issue(['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $root, 'client');
        $transport = (new FakeTransport())->respond('http://ocsp.example.test/response', 'invalid')->respond('http://crl.example.test/list.crl', $pki->crl($client['pem'], $root, true));
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options());
        self::assertSame('revoked', $validator->validate($client['pem'])->reason);
        $badCa = $pki->issue(['CN' => 'No certificate signing'], profile: 'ca_no_sign');
        $store->publish([hash('sha256', TestPki::der($badCa['pem'])) => ['pem' => $badCa['pem'], 'country' => 'ES', 'service' => 'CA/QC']], force: true);
        self::assertSame('untrusted', $validator->validate($pki->issue(['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $badCa, 'client')['pem'])->reason);
        $limitedRoot = $pki->issue(['CN' => 'Path length zero'], profile: 'ca_pathlen0');
        $intermediate = $pki->issue(['CN' => 'Intermediate'], $limitedRoot, 'ca');
        $store->publish([hash('sha256', TestPki::der($limitedRoot['pem'])) => ['pem' => $limitedRoot['pem'], 'country' => 'ES', 'service' => 'CA/QC']], force: true);
        $withIntermediate = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options(), intermediates: [$intermediate['pem']]);
        self::assertSame('untrusted', $withIntermediate->validate($pki->issue(['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $intermediate, 'client')['pem'])->reason);
    }
    public function testExpiredAnchorRejectsOtherwiseValidClient(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Short lived CA'], profile: 'ca', days: 0);
        $client = $pki->issue(['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $root, 'client');
        $store = new TrustStore($this->dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'CA/QC']]);
        usleep(1_100_000);
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options());
        self::assertSame('untrusted', $validator->validate($client['pem'])->reason);
    }

}
