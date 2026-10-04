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
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;

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
        $store->publish([$fingerprint => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
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
        $store->publish([$fingerprint => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
        $transport = new FakeTransport();
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options());
        $subject = ['CN' => 'Imaginary Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'];
        $client = $pki->issue($subject, $root, 'client');
        $transport->respond('http://ocsp.example.test/response', $pki->ocspResponse($client['pem'], $root, true));
        self::assertSame('revoked', $validator->validate($client['pem'])->reason);
        self::assertSame('expired', $validator->validate($client['pem'], new DateTimeImmutable('+2 years'))->reason);
        $expired = $pki->issue($subject, $root, 'client', 0);
        self::assertSame('expired', $validator->validate($expired['pem'], new DateTimeImmutable('+1 minute'))->reason);
        self::assertSame('no_authentication_usage', $validator->validate($pki->issue($subject, $root, 'client_no_auth')['pem'])->reason);
        self::assertSame('untrusted', $validator->validate($pki->issue($subject, null, 'client')['pem'])->reason);
    }

    public function testSignatureUsageAcceptsSigningKeyUsageWithCompatibleExtendedUsage(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Test root', 'C' => 'ES'], profile: 'ca');
        $store = new TrustStore($this->dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
        $transport = new FakeTransport();
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options(profiles: ['signature' => ['usage' => 'signature']]));
        $subject = ['CN' => 'Signer', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'];

        foreach (['sign_no_eku', 'sign_email', 'sign_document', 'sign_any', 'sign_fnmt'] as $certificateProfile) {
            $client = $pki->issue($subject, $root, $certificateProfile);
            $transport->respond('http://ocsp.example.test/response', $pki->ocspResponse($client['pem'], $root));
            $result = $validator->validate($client['pem'], profile: 'signature');
            self::assertTrue($result->valid, $certificateProfile . ': ' . $result->reason);
            self::assertSame('signature', $result->profile);
        }
    }

    public function testSignatureUsageRejectsEncryptionAndIncompatibleExtendedUsage(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Test root', 'C' => 'ES'], profile: 'ca');
        $store = new TrustStore($this->dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options(profiles: ['signature' => ['usage' => 'signature']]));
        $subject = ['CN' => 'Signer', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'];

        foreach (['encrypt_only', 'sign_wrong_eku'] as $certificateProfile) {
            $result = $validator->validate($pki->issue($subject, $root, $certificateProfile)['pem'], profile: 'signature');
            self::assertSame('no_signature_usage', $result->reason, $certificateProfile);
        }
    }

    public function testAuthenticationUsageRemainsTheDefaultForNamedProfiles(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Test root', 'C' => 'ES'], profile: 'ca');
        $store = new TrustStore($this->dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options(profiles: ['login' => []]));
        $subject = ['CN' => 'Signer', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'];

        self::assertSame('no_authentication_usage', $validator->validate($pki->issue($subject, $root, 'sign_email')['pem'], profile: 'login')->reason);
        self::assertSame('no_authentication_usage', $validator->validate($pki->issue($subject, $root, 'sign_no_eku')['pem'])->reason);
    }

    public function testProfileRejectsNonStringUsageAsConfigurationError(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid eIDAS profile setting: usage');
        new Options(profiles: ['signature' => ['usage' => false]]);
    }

    public function testFallsBackToSignedCrlAndCachesVerifiedStatus(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Fictional CRL CA'], profile: 'ca');
        $store = new TrustStore($this->dir . '/trust');
        $fingerprint = hash('sha256', TestPki::der($root['pem']));
        $store->publish([$fingerprint => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
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
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
        $transport = new FakeTransport();
        $strict = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options());
        $subject = ['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'];
        $client = $pki->issue($subject, $root, 'client');
        self::assertSame('not_yet_valid', $strict->validate($client['pem'], new DateTimeImmutable('-1 day'))->reason);
        self::assertSame('revocation_unavailable', $strict->validate($client['pem'])->reason);
        $soft = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options(softFailRevocation: true));
        self::assertTrue($soft->validate($client['pem'])->valid);
        $qualified = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options(profiles: ['signature' => ['qualified_required' => true]]));
        self::assertSame('qualified_required', $qualified->validate($pki->issue($subject, $root, 'client_no_qc')['pem'], profile: 'signature')->reason);
        self::assertSame('qualified_required', $qualified->validate($pki->issue($subject, $root, 'client_fake_qc')['pem'], profile: 'signature')->reason);
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
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
        $client = $pki->issue(['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $root, 'client');
        $transport = (new FakeTransport())->respond('http://ocsp.example.test/response', 'invalid')->respond('http://crl.example.test/list.crl', $pki->crl($client['pem'], $root, true));
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options());
        self::assertSame('revoked', $validator->validate($client['pem'])->reason);
        $badCa = $pki->issue(['CN' => 'No certificate signing'], profile: 'ca_no_sign');
        $store->publish([hash('sha256', TestPki::der($badCa['pem'])) => ['pem' => $badCa['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]], force: true);
        self::assertSame('untrusted', $validator->validate($pki->issue(['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $badCa, 'client')['pem'])->reason);
        $limitedRoot = $pki->issue(['CN' => 'Path length zero'], profile: 'ca_pathlen0');
        $intermediate = $pki->issue(['CN' => 'Intermediate'], $limitedRoot, 'ca');
        $store->publish([hash('sha256', TestPki::der($limitedRoot['pem'])) => ['pem' => $limitedRoot['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]], force: true);
        $withIntermediate = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options(), intermediates: [$intermediate['pem']]);
        self::assertSame('untrusted', $withIntermediate->validate($pki->issue(['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $intermediate, 'client')['pem'])->reason);
    }
    public function testExpiredAnchorRejectsOtherwiseValidClient(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Short lived CA'], profile: 'ca', days: 0);
        $client = $pki->issue(['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $root, 'client');
        $store = new TrustStore($this->dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
        usleep(1_100_000);
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options());
        self::assertSame('untrusted', $validator->validate($client['pem'])->reason);
    }

    public function testDnieAuthenticationPolicyAiaPurposeAndIdentity(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'AC RAIZ DNIE 2', 'C' => 'ES'], profile: 'ca');
        $intermediate = $pki->issue(['CN' => 'AC DNIE 004', 'C' => 'ES'], $root, 'ca');
        $store = new TrustStore($this->dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
        $transport = (new FakeTransport())->respond('http://aia.example.test/issuer.crt', TestPki::der($intermediate['pem']));
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options(), aiaTransport: $transport);
        $subject = ['CN' => 'Example (AUTENTICACION)', 'serialNumber' => '12345678Z', 'C' => 'ES'];

        foreach (['dnie_auth' => true, 'dnie_no_eku' => true, 'dnie_versioned' => true, 'dnie_wrong_policy' => true, 'dnie_wrong_eku' => false, 'dnie_bad_ku' => true] as $profile => $expected) {
            $client = $pki->issue($subject, $intermediate, $profile);
            $transport->respond('http://ocsp.example.test/response', $pki->ocspResponse($client['pem'], $intermediate));
            $result = $validator->validate($client['pem']);
            self::assertSame($expected, $result->valid, $profile . ': ' . $result->reason);
            if ($expected) {
                self::assertSame('12345678Z', $result->identity?->identifier);
            } else {
                self::assertSame('no_authentication_usage', $result->reason);
            }
        }
        self::assertCount(1, array_filter($transport->sent, static fn(array $request): bool => $request['url'] === 'http://aia.example.test/issuer.crt'));

        $badSerial = $pki->issue(['CN' => 'Example', 'serialNumber' => '12345678A', 'C' => 'ES'], $intermediate, 'dnie_auth');
        $transport->respond('http://ocsp.example.test/response', $pki->ocspResponse($badSerial['pem'], $intermediate));
        self::assertSame('no_personal_identity', $validator->validate($badSerial['pem'])->reason);

        $otherRoot = $pki->issue(['CN' => 'Other Root', 'C' => 'ES'], profile: 'ca');
        $otherIntermediate = $pki->issue(['CN' => 'Other Intermediate', 'C' => 'ES'], $otherRoot, 'ca');
        $otherClient = $pki->issue($subject, $otherIntermediate, 'dnie_auth');
        $otherTransport = (new FakeTransport())->respond('http://aia.example.test/issuer.crt', TestPki::der($otherIntermediate['pem']));
        $untrusted = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($otherTransport, new InMemoryRevocationCache()), new Options(), aiaTransport: $otherTransport);
        self::assertSame('untrusted', $untrusted->validate($otherClient['pem'])->reason);

        $configured = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options(), intermediates: [$intermediate['pem']], aiaTransport: new FakeTransport());
        $client = $pki->issue($subject, $intermediate, 'dnie_auth');
        $transport->respond('http://ocsp.example.test/response', $pki->ocspResponse($client['pem'], $intermediate));
        self::assertTrue($configured->validate($client['pem'])->valid);
        $offlineTransport = new FakeTransport();
        $offline = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options(profiles: ['offline' => ['aia_fetch' => false]]), aiaTransport: $offlineTransport);
        $offlineResult = $offline->validate($client['pem'], profile: 'offline');
        self::assertSame('untrusted', $offlineResult->reason);
        self::assertSame('offline', $offlineResult->profile);
        self::assertCount(0, $offlineTransport->sent);
        $blockedHost = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options(aiaAllowedHosts: ['ca.example.test']), aiaTransport: $offlineTransport);
        self::assertSame('untrusted', $blockedHost->validate($client['pem'])->reason);
        self::assertCount(0, $offlineTransport->sent);
        $restricted = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options(profiles: ['restricted' => ['authentication_policies' => ['ES' => ['2.16.724.1.2.2.2.4']]]]), intermediates: [$intermediate['pem']]);
        self::assertTrue($restricted->validate($client['pem'], profile: 'restricted')->valid);
        $wrongPolicy = $pki->issue($subject, $intermediate, 'dnie_wrong_policy');
        self::assertSame('authentication_policy_mismatch', $restricted->validate($wrongPolicy['pem'], profile: 'restricted')->reason);

        $noForeStore = new TrustStore($this->dir . '/trust');
        $noForeStore->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => false]], force: true);
        $noFore = new CertificateValidator(new CertificateParser(), $noForeStore, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options(), intermediates: [$intermediate['pem']]);
        self::assertSame('untrusted', $noFore->validate($client['pem'])->reason);
    }

    public function testNamedProfilesSeparateDnieQualificationPersonTypesAndRevocation(): void
    {
        $pki = new TestPki();
        $dnieRoot = $pki->issue(['CN' => 'AC RAIZ DNIE 2', 'C' => 'ES'], profile: 'ca');
        $dnieIssuer = $pki->issue(['CN' => 'AC DNIE 004', 'C' => 'ES'], $dnieRoot, 'ca');
        $fnmtRoot = $pki->issue(['CN' => 'AC FNMT Usuarios', 'C' => 'ES'], profile: 'ca');
        $store = new TrustStore($this->dir . '/trust');
        $entry = static fn(array $ca): array => ['pem' => $ca['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true];
        $store->publish([
            hash('sha256', TestPki::der($dnieRoot['pem'])) => $entry($dnieRoot),
            hash('sha256', TestPki::der($fnmtRoot['pem'])) => $entry($fnmtRoot),
        ]);
        $subject = ['CN' => 'Citizen', 'serialNumber' => '12345678Z', 'C' => 'ES'];
        $dnie = $pki->issue($subject, $dnieIssuer, 'dnie_no_eku');
        $fnmt = $pki->issue(['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $fnmtRoot, 'client');
        $representative = $pki->issue(['CN' => 'Representative', 'serialNumber' => 'IDCES-00000000T', 'organizationIdentifier' => 'VATES-B00000000', 'C' => 'ES'], $fnmtRoot, 'client');
        $seal = $pki->issue(['CN' => 'Company', 'organizationIdentifier' => 'VATES-B00000000', 'C' => 'ES'], $fnmtRoot, 'client');
        $transport = (new FakeTransport())
            ->respond('http://ocsp.example.test/response', $pki->ocspResponse($dnie['pem'], $dnieIssuer))
            ->respond('http://aia.example.test/issuer.crt', TestPki::der($dnieIssuer['pem']));
        $options = new Options(profiles: [
            'login' => ['countries' => ['ES'], 'dnie' => true, 'qualified_required' => false, 'person_types' => ['natural', 'representative'], 'soft_fail_revocation' => false],
            'signature' => ['countries' => ['ES'], 'dnie' => true, 'qualified_required' => true, 'person_types' => ['natural', 'representative'], 'soft_fail_revocation' => false],
            'onboarding' => ['countries' => ['ES'], 'dnie' => false, 'qualified_required' => false, 'person_types' => ['natural', 'representative'], 'soft_fail_revocation' => false],
            'natural_only' => ['person_types' => ['natural']],
            'seal' => ['person_types' => ['legal'], 'qualified_required' => true],
            'soft' => ['soft_fail_revocation' => true],
        ]);
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), $options, aiaTransport: $transport);
        $loginResult = $validator->validate($dnie['pem'], profile: 'login');
        self::assertTrue($loginResult->valid);
        self::assertSame('login', $loginResult->profile);
        self::assertSame('dnie_disabled_for_profile', $validator->validate($dnie['pem'], profile: 'onboarding')->reason);
        self::assertSame('qualified_required', $validator->validate($dnie['pem'], profile: 'signature')->reason);
        foreach (['login', 'signature', 'onboarding'] as $profile) {
            $transport->respond('http://ocsp.example.test/response', $pki->ocspResponse($fnmt['pem'], $fnmtRoot));
            self::assertTrue($validator->validate($fnmt['pem'], profile: $profile)->valid, $profile);
        }
        self::assertSame('person_type_not_allowed', $validator->validate($representative['pem'], profile: 'natural_only')->reason);
        self::assertSame('person_type_not_allowed', $validator->validate($seal['pem'], profile: 'login')->reason);
        $transport->respond('http://ocsp.example.test/response', $pki->ocspResponse($seal['pem'], $fnmtRoot));
        self::assertTrue($validator->validate($seal['pem'], profile: 'seal')->valid);
        self::assertSame('revocation_unavailable', $validator->validate($representative['pem'], profile: 'login')->reason);
        self::assertTrue($validator->validate($representative['pem'], profile: 'soft')->valid);
    }

    public function testUnknownProfileIsConfigurationErrorBeforeCertificateParsing(): void
    {
        $validator = new CertificateValidator(new CertificateParser(), new TrustStore($this->dir . '/trust'), new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options());
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown eIDAS validation profile: absent');
        $validator->validate('not a certificate', profile: 'absent');
    }

    public function testAiaIsLimitedToLeafAndOneRequestAndSharesFailures(): void
    {
        $pki = new TestPki();
        $anchor = $pki->issue(['CN' => 'Trusted anchor'], profile: 'ca');
        $foreignRoot = $pki->issue(['CN' => 'Foreign root'], profile: 'ca');
        $foreignIssuer = $pki->issue(['CN' => 'Foreign issuer'], $foreignRoot, 'ca');
        $store = new TrustStore($this->dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($anchor['pem'])) => ['pem' => $anchor['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
        $transport = (new FakeTransport())->respond('http://aia.example.test/issuer.crt', TestPki::der($foreignIssuer['pem']));
        $selfSigned = $pki->issue(['CN' => 'Self signed'], profile: 'aia_many_self');
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options(), aiaTransport: $transport);
        self::assertSame('untrusted', $validator->validate($selfSigned['pem'])->reason);
        self::assertCount(0, $transport->sent);

        $leaf = $pki->issue(['CN' => 'Client', 'C' => 'ES'], $foreignIssuer, 'dnie_auth');
        $cached = null;
        $cache = $this->createMock(CacheInterface::class);
        $cache->method('get')->willReturnCallback(static function (string $key) use (&$cached): mixed {
            return $cached;
        });
        $cache->method('set')->willReturnCallback(static function (string $key, mixed $value, int $ttl) use (&$cached): bool {
            $cached = $value;
            self::assertSame(300, $ttl);

            return true;
        });
        for ($i = 0; $i < 2; $i++) {
            $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options(), aiaTransport: $transport, aiaCacheStore: $cache);
            self::assertSame('untrusted', $validator->validate($leaf['pem'])->reason);
        }
        self::assertCount(1, $transport->sent);
        self::assertSame(4, $transport->sent[0]['timeout']);
    }

    public function testIntermediatePathLengthUsesActualDepth(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'Root'], profile: 'ca');
        $limited = $pki->issue(['CN' => 'Limited'], $root, 'ca_pathlen0');
        $lower = $pki->issue(['CN' => 'Lower'], $limited, 'ca');
        $leaf = $pki->issue(['CN' => 'Client', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $lower, 'client');
        $store = new TrustStore($this->dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options(), intermediates: [$lower['pem'], $limited['pem']]);
        self::assertSame('untrusted', $validator->validate($leaf['pem'])->reason);
    }

    public function testSuccessfulAiaDownloadIsSharedAcrossValidators(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'AC RAIZ DNIE 2', 'C' => 'ES'], profile: 'ca');
        $issuer = $pki->issue(['CN' => 'AC DNIE 004', 'C' => 'ES'], $root, 'ca');
        $leaf = $pki->issue(['CN' => 'Citizen', 'serialNumber' => '12345678Z', 'C' => 'ES'], $issuer, 'dnie_auth');
        $store = new TrustStore($this->dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', 'fore_signatures' => true]]);
        $transport = (new FakeTransport())->respond('http://aia.example.test/issuer.crt', TestPki::der($issuer['pem']));
        $cached = null;
        $cache = $this->createMock(CacheInterface::class);
        $cache->method('get')->willReturnCallback(static function (string $key) use (&$cached): mixed {
            return $cached;
        });
        $cache->method('set')->willReturnCallback(static function (string $key, mixed $value, int $ttl) use (&$cached): bool {
            $cached = $value;
            self::assertSame(3600, $ttl);

            return true;
        });
        for ($i = 0; $i < 2; $i++) {
            $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options(softFailRevocation: true), aiaTransport: $transport, aiaCacheStore: $cache);
            self::assertTrue($validator->validate($leaf['pem'])->valid);
        }
        self::assertCount(1, $transport->sent);
    }

}
