<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use DateTimeImmutable;
use DOMDocument;
use DOMXPath;
use Iberfacil\EidasCertAuth\Cache\InMemoryRevocationCache;
use Iberfacil\EidasCertAuth\Certificate\CertificateParser;
use Iberfacil\EidasCertAuth\Certificate\CertificateValidator;
use Iberfacil\EidasCertAuth\Certificate\RevocationChecker;
use Iberfacil\EidasCertAuth\Exceptions\TrustListRejected;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Tests\Support\SignedLists;
use Iberfacil\EidasCertAuth\Tests\Support\TestPki;
use Iberfacil\EidasCertAuth\Transport\FakeTransport;
use Iberfacil\EidasCertAuth\Trust\TrustListImporter;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use Iberfacil\EidasCertAuth\Trust\XmlSignatureVerifier;
use PHPUnit\Framework\TestCase;
use RobRichards\XMLSecLibs\XMLSecurityDSig;

final class SecurityRegressionTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/eidas-security-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/.trust.*') ?: [] as $generation) {
            if (is_dir($generation)) {
                foreach (glob($generation . '/*') ?: [] as $file) {
                    unlink($file);
                }
                rmdir($generation);
            } else {
                unlink($generation);
            }
        }
        if (is_link($this->dir . '/trust')) {
            unlink($this->dir . '/trust');
        }
        if (is_dir($this->dir . '/trust')) {
            rmdir($this->dir . '/trust');
        }
        rmdir($this->dir);
    }

    public function testInjectedServicesInObjectKeyInfoAndUnsignedPropertiesNeverBecomeAnchors(): void
    {
        $pki = new TestPki();
        $signer = $pki->issue(['CN' => 'National signer']);
        $good = $pki->issue(['CN' => 'Good CA'], profile: 'ca');
        $evil = $pki->issue(['CN' => 'Attacker CA'], profile: 'ca');
        $pins = [self::fingerprint($signer['pem'])];
        $signed = SignedLists::sign(SignedLists::tsl('ES', [$good['pem']]), $signer);
        $service = self::service($evil['pem']);
        foreach (['Object' => '<ds:Object>' . $service . '</ds:Object>', 'KeyInfo' => '<ds:KeyInfo>' . $service . '</ds:KeyInfo>', 'UnsignedProperties' => '<ds:Object><UnsignedProperties>' . $service . '</UnsignedProperties></ds:Object>'] as $location => $fragment) {
            $tampered = str_replace('</ds:Signature>', $fragment . '</ds:Signature>', $signed);
            $store = new TrustStore($this->dir . '/trust');
            $importer = new TrustListImporter(new FakeTransport(), new XmlSignatureVerifier(), $store, new Options());
            self::assertSame(1, $importer->importTsl($tampered, 'ES', $pins)->count, $location);
            self::assertArrayNotHasKey(self::fingerprint($evil['pem']), $store->certificates(), $location);
            self::assertStringNotContainsString($evil['pem'], (string) file_get_contents($store->path . '/bundle.pem'), $location);
        }
    }

    public function testEndToEndLotlImportDoesNotTrustInjectedCaOrItsClient(): void
    {
        $pki = new TestPki();
        $lotlSigner = $pki->issue(['CN' => 'LOTL signer']);
        $tslSigner = $pki->issue(['CN' => 'TSL signer']);
        $good = $pki->issue(['CN' => 'Good CA'], profile: 'ca');
        $evil = $pki->issue(['CN' => 'Attacker CA'], profile: 'ca');
        $tsl = SignedLists::sign(SignedLists::tsl('ES', [$good['pem']]), $tslSigner);
        $tsl = str_replace('</ds:Signature>', '<ds:Object>' . self::service($evil['pem']) . '</ds:Object></ds:Signature>', $tsl);
        $url = 'https://lists.example.test/es.xml';
        $options = new Options(lotlSignerFingerprints: [self::fingerprint($lotlSigner['pem'])]);
        $store = new TrustStore($this->dir . '/trust');
        $transport = (new FakeTransport())->respond($url, $tsl);
        $importer = new TrustListImporter($transport, new XmlSignatureVerifier(), $store, $options);
        self::assertSame(1, $importer->importLotl(SignedLists::sign(SignedLists::lotl('ES', $url, $tslSigner['pem']), $lotlSigner))->count);
        $victim = $pki->issue(['CN' => 'Victim', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $evil, 'client');
        $transport->respond('http://ocsp.example.test/response', $pki->ocspResponse($victim['pem'], $evil));
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), $options);
        self::assertSame('untrusted', $validator->validate($victim['pem'])->reason);
    }

    public function testInjectedLotlPointerCannotAddUnsignedCountry(): void
    {
        $pki = new TestPki();
        $lotlSigner = $pki->issue(['CN' => 'LOTL signer']);
        $esSigner = $pki->issue(['CN' => 'ES signer']);
        $chSigner = $pki->issue(['CN' => 'CH attacker']);
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $esUrl = 'https://lists.example.test/es.xml';
        $chUrl = 'https://evil.example.test/ch.xml';
        $lotl = SignedLists::sign(SignedLists::lotl('ES', $esUrl, $esSigner['pem']), $lotlSigner);
        $pointer = '<OtherTSLPointer xmlns="http://uri.etsi.org/02231/v2#"><TSLLocation>' . $chUrl . '</TSLLocation><ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>' . base64_encode(TestPki::der($chSigner['pem'])) . '</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities><AdditionalInformation><OtherInformation><SchemeTerritory>CH</SchemeTerritory></OtherInformation></AdditionalInformation></OtherTSLPointer>';
        $injections = [
            '<ds:Object>' . $pointer . '</ds:Object>',
            '<ds:KeyInfo>' . $pointer . '</ds:KeyInfo>',
            '<ds:Object><UnsignedProperties>' . $pointer . '</UnsignedProperties></ds:Object>',
        ];
        $transport = (new FakeTransport())->respond($esUrl, SignedLists::sign(SignedLists::tsl('ES', [$ca['pem']]), $esSigner))->respond($chUrl, SignedLists::sign(SignedLists::tsl('CH', [$ca['pem']]), $chSigner));
        $options = new Options(countries: ['ES', 'CH'], lotlSignerFingerprints: [self::fingerprint($lotlSigner['pem'])]);
        $importer = new TrustListImporter($transport, new XmlSignatureVerifier(), new TrustStore($this->dir . '/trust'), $options);
        $rejected = 0;
        foreach ($injections as $fragment) {
            try {
                $importer->importLotl(str_replace('</ds:Signature>', $fragment . '</ds:Signature>', $lotl));
                self::fail('Unsigned country pointer was followed.');
            } catch (TrustListRejected) {
                $rejected++;
            }
        }
        self::assertSame(3, $rejected);
    }

    public function testMissingNextUpdateRollbackAndQualifiersFailClosed(): void
    {
        $pki = new TestPki();
        $signer = $pki->issue(['CN' => 'Signer']);
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $pins = [self::fingerprint($signer['pem'])];
        $store = new TrustStore($this->dir . '/trust');
        $importer = new TrustListImporter(new FakeTransport(), new XmlSignatureVerifier(), $store, new Options());
        $base = SignedLists::tsl('ES', [$ca['pem']]);
        $higher = str_replace('<TSLSequenceNumber>1</TSLSequenceNumber>', '<TSLSequenceNumber>2</TSLSequenceNumber>', $base);
        self::assertSame(1, $importer->importTsl(SignedLists::sign($higher, $signer), 'ES', $pins)->count);
        $manifest = json_decode((string) file_get_contents($store->path . '/manifest.json'), true);
        self::assertSame(2, $manifest['sequences']['ES']);
        self::assertArrayHasKey('ES', $manifest['issue_dates']);
        try {
            $importer->importTsl(SignedLists::sign($base, $signer), 'ES', $pins, force: true);
            self::fail('Force bypassed sequence rollback.');
        } catch (TrustListRejected) {
            self::assertCount(1, $store->certificates());
        }
        foreach ([
            $base,
            preg_replace('#<NextUpdate>.*?</NextUpdate>#', '', $higher),
            str_replace('ForeSignatures', 'ForeSeals', $higher),
            str_replace('</ServiceInformationExtensions>', '<Extension><sie:Qualifications xmlns:sie="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"><sie:QualificationElement><sie:Qualifiers><sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified"/></sie:Qualifiers></sie:QualificationElement></sie:Qualifications></Extension></ServiceInformationExtensions>', $higher),
            str_replace('</ServiceInformationExtensions>', '<Extension><sie:Qualifications xmlns:sie="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"><sie:QualificationElement><sie:Qualifiers><sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson"/></sie:Qualifiers></sie:QualificationElement></sie:Qualifications></Extension></ServiceInformationExtensions>', $higher),
        ] as $candidate) {
            try {
                $importer->importTsl(SignedLists::sign((string) $candidate, $signer), 'ES', $pins);
                self::fail('Unsafe update was accepted.');
            } catch (TrustListRejected) {
                self::assertCount(1, $store->certificates());
            }
        }
    }

    public function testDoctypeOversizeAndSignatureStructuralChangesAreRejected(): void
    {
        $pki = new TestPki();
        $signer = $pki->issue(['CN' => 'Signer']);
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $signed = SignedLists::sign(SignedLists::tsl('ES', [$ca['pem']]), $signer);
        $pins = [self::fingerprint($signer['pem'])];
        $doctype = '<?xml version="1.0"?><!DOCTYPE TrustServiceStatusList [<!ENTITY x "x">]>' . preg_replace('/^<\?xml[^>]+>/', '', $signed);
        $utf16 = "\xff\xfe" . mb_convert_encoding(str_replace('encoding="1.0"', 'encoding="UTF-16"', $doctype), 'UTF-16LE', 'UTF-8');
        $mutations = [
            $doctype,
            $utf16,
            str_repeat(' ', 20_000_001),
            str_replace('</ds:Signature>', '</ds:Signature>' . self::signatureNode($signed), $signed),
            str_replace('<ds:Signature', '<Wrapper><ds:Signature', str_replace('</ds:Signature>', '</ds:Signature></Wrapper>', $signed)),
            str_replace('http://www.w3.org/2001/10/xml-exc-c14n#', XMLSecurityDSig::C14N, $signed),
            str_replace(XMLSecurityDSig::SHA256, XMLSecurityDSig::SHA1, $signed),
            str_replace('rsa-sha256', 'rsa-sha1', $signed),
            str_replace('URI=""', 'URI="https://evil.example.test/x"', $signed),
            str_replace('http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/TR/1999/REC-xpath-19991116', $signed),
            str_replace('http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/TR/1999/REC-xslt-19991116', $signed),
            str_replace('URI=""', 'URI="#child"', str_replace('<SchemeInformation>', '<SchemeInformation Id="child">', $signed)),
        ];
        $verifier = new XmlSignatureVerifier();
        $rejected = 0;
        foreach ($mutations as $index => $xml) {
            try {
                $verifier->verify($xml, $pins);
                self::fail('Mutation ' . $index . ' was accepted.');
            } catch (TrustListRejected) {
                $rejected++;
            }
        }
        self::assertCount($rejected, $mutations);
    }

    public function testStoreRejectsCorruptionAndKeepsOldGenerationReadable(): void
    {
        $pki = new TestPki();
        $a = $pki->issue(['CN' => 'A'], profile: 'ca');
        $b = $pki->issue(['CN' => 'B'], profile: 'ca');
        $store = new TrustStore($this->dir . '/trust');
        $entry = static fn(string $pem): array => ['pem' => $pem, 'country' => 'ES', 'service' => 'CA/QC'];
        $store->publish([self::fingerprint($a['pem']) => $entry($a['pem'])]);
        $oldPath = realpath($store->path);
        self::assertIsString($oldPath);
        self::assertCount(1, $store->certificates());
        $store->publish([self::fingerprint($b['pem']) => $entry($b['pem'])], force: true);
        self::assertFileExists($oldPath . '/manifest.json');
        self::assertArrayHasKey(self::fingerprint($b['pem']), $store->certificates());
        file_put_contents($store->path . '/manifest.json', '{broken');
        try {
            $store->publish([self::fingerprint($a['pem']) => $entry($a['pem'])]);
            self::fail('Corrupt manifest was accepted.');
        } catch (TrustListRejected) {
            self::assertSame([], $store->certificates());
        }
        unlink($store->path . '/manifest.json');
        $this->expectException(TrustListRejected::class);
        $store->publish([self::fingerprint($a['pem']) => $entry($a['pem'])]);
    }

    public function testStoreRetentionIsPerCountryAndForceOnlyOverridesCount(): void
    {
        $pki = new TestPki();
        $entries = [];
        foreach (['ES', 'PT'] as $country) {
            for ($i = 0; $i < 5; $i++) {
                $ca = $pki->issue(['CN' => $country . $i], profile: 'ca');
                $entries[self::fingerprint($ca['pem'])] = ['pem' => $ca['pem'], 'country' => $country, 'service' => 'CA/QC'];
            }
        }
        $store = new TrustStore($this->dir . '/trust');
        $store->publish($entries);
        $pt = array_filter($entries, static fn(array $entry): bool => $entry['country'] === 'PT');
        $es = array_filter($entries, static fn(array $entry): bool => $entry['country'] === 'ES');
        self::assertTrue($store->publish($es, dryRun: true)->retentionRejected);
        self::assertSame(5, $store->publish($es, force: true)->count);
        $this->expectException(TrustListRejected::class);
        $store->publish([], force: true);
    }

    public function testRetentionGuardBoundaryAtSeventyNineAndEightyPercent(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);
        $entries = [];
        for ($i = 0; $i < 100; $i++) {
            $csr = openssl_csr_new(['CN' => 'Count fixture ' . $i], $key, ['digest_alg' => 'sha256']);
            self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);
            $certificate = openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256'], $i + 1);
            self::assertInstanceOf(\OpenSSLCertificate::class, $certificate);
            self::assertTrue(openssl_x509_export($certificate, $pem));
            $entries[self::fingerprint($pem)] = ['pem' => $pem, 'country' => 'ES', 'service' => 'CA/QC'];
        }
        $store = new TrustStore($this->dir . '/trust');
        $store->publish($entries);
        self::assertFalse($store->publish(array_slice($entries, 0, 80, true), dryRun: true)->retentionRejected);
        self::assertTrue($store->publish(array_slice($entries, 0, 79, true), dryRun: true)->retentionRejected);
    }

    public function testStoreExpiryAndDirectoryLivePathFailClosed(): void
    {
        $pki = new TestPki();
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $entry = [self::fingerprint($ca['pem']) => ['pem' => $ca['pem'], 'country' => 'ES', 'service' => 'CA/QC']];
        $store = new TrustStore($this->dir . '/trust', maximumAgeSeconds: 1);
        $store->publish($entry, nextUpdate: new DateTimeImmutable('+1 day'));
        self::assertCount(1, $store->certificates());
        $manifestPath = $store->path . '/manifest.json';
        $manifest = json_decode((string) file_get_contents($manifestPath), true);
        $manifest['next_update'] = '2020-01-01T00:00:00+00:00';
        file_put_contents($manifestPath, json_encode($manifest));
        self::assertCount(0, $store->certificates());
        $manifest['next_update'] = '2099-01-01T00:00:00+00:00';
        $manifest['generated_at'] = '2020-01-01T00:00:00+00:00';
        file_put_contents($manifestPath, json_encode($manifest));
        self::assertCount(0, $store->certificates());
        unlink($store->path);
        mkdir($store->path);
        $this->expectException(TrustListRejected::class);
        $store->publish($entry);
    }

    public function testPublishWaitsForGenerationLock(): void
    {
        $pki = new TestPki();
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $entry = [self::fingerprint($ca['pem']) => ['pem' => $ca['pem'], 'country' => 'ES', 'service' => 'CA/QC']];
        $store = new TrustStore($this->dir . '/trust');
        $store->publish($entry);
        $ready = $this->dir . '/ready';
        $script = '$f=fopen($argv[1], "c"); flock($f, LOCK_EX); file_put_contents($argv[2], "ready"); usleep(900000); flock($f, LOCK_UN); fclose($f);';
        $process = proc_open(['php', '-r', $script, $this->dir . '/.trust.lock', $ready], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($process);
        try {
            $deadline = microtime(true) + 2;
            while (! is_file($ready) && microtime(true) < $deadline) {
                usleep(10000);
            }
            self::assertFileExists($ready);
            $start = microtime(true);
            $store->publish($entry);
            self::assertGreaterThan(0.4, microtime(true) - $start);
        } finally {
            foreach ($pipes as $pipe) {
                fclose($pipe);
            }
            proc_close($process);
            @unlink($ready);
        }
    }

    public function testLegacyManifestRequiresRefreshAndCanBeMigrated(): void
    {
        $pki = new TestPki();
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $entry = [self::fingerprint($ca['pem']) => ['pem' => $ca['pem'], 'country' => 'ES', 'service' => 'CA/QC']];
        $store = new TrustStore($this->dir . '/trust');
        $store->publish($entry);
        $manifestPath = $store->path . '/manifest.json';
        $manifest = json_decode((string) file_get_contents($manifestPath), true);
        file_put_contents($manifestPath, json_encode($manifest['certificates']));
        self::assertCount(0, $store->certificates());
        $store->publish($entry, sequences: ['ES' => 1], nextUpdate: new DateTimeImmutable('+1 day'), issueDates: ['ES' => '2026-01-01T00:00:00+00:00']);
        self::assertCount(1, $store->certificates());
    }

    private static function fingerprint(string $pem): string
    {
        return hash('sha256', TestPki::der($pem));
    }

    private static function service(string $pem): string
    {
        return '<TSPService xmlns="http://uri.etsi.org/02231/v2#"><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime><ServiceDigitalIdentity><DigitalId><X509Certificate>' . base64_encode(TestPki::der($pem)) . '</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceInformation></TSPService>';
    }

    private static function signatureNode(string $signed): string
    {
        $document = new DOMDocument();
        $document->loadXML($signed);
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $nodes = $xpath->query('//ds:Signature');
        $signature = $nodes === false ? null : $nodes->item(0);
        if (! $signature instanceof \DOMNode) {
            throw new \RuntimeException('Missing test signature.');
        }

        return (string) $document->saveXML($signature);
    }
}
