<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use DateTimeImmutable;
use Iberfacil\EidasCertAuth\Exceptions\TrustListRejected;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Tests\Support\SignedLists;
use Iberfacil\EidasCertAuth\Tests\Support\TestPki;
use Iberfacil\EidasCertAuth\Transport\FakeTransport;
use Iberfacil\EidasCertAuth\Trust\TrustListImporter;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use Iberfacil\EidasCertAuth\Trust\XmlSignatureVerifier;
use PHPUnit\Framework\TestCase;

final class TrustListImporterTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/eidas-store-test-' . bin2hex(random_bytes(6));
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

    public function testSignedLotlImportsOnlyGrantedQcAndPreservesStoreOnBadSignature(): void
    {
        $pki = new TestPki();
        $lotlSigner = $pki->issue(['CN' => 'Test LOTL signer', 'C' => 'EU']);
        $tslSigner = $pki->issue(['CN' => 'Test national signer', 'C' => 'ES']);
        $ca = $pki->issue(['CN' => 'Test CA one', 'C' => 'ES'], profile: 'ca');
        $withdrawn = $pki->issue(['CN' => 'Test CA two', 'C' => 'ES'], profile: 'ca');
        $url = 'https://lists.example.test/es.xml';
        $transport = (new FakeTransport())->respond($url, SignedLists::sign(SignedLists::tsl('ES', [$ca['pem']]), $tslSigner));
        $options = new Options(lotlSignerFingerprints: [hash('sha256', TestPki::der($lotlSigner['pem']))]);
        $store = new TrustStore($this->dir . '/trust');
        $importer = new TrustListImporter($transport, new XmlSignatureVerifier(), $store, $options);
        $lotl = SignedLists::sign(SignedLists::lotl('ES', $url, $tslSigner['pem']), $lotlSigner);
        $result = $importer->importLotl($lotl);
        self::assertSame(1, $result->count);
        self::assertCount(1, $store->certificates());
        self::assertTrue(is_link($store->path));
        self::assertFileExists($store->path . '/bundle.pem');

        $tampered = str_replace('lists.example.test', 'evil.example.test', $lotl);
        $this->expectException(TrustListRejected::class);
        try {
            $importer->importLotl($tampered);
        } finally {
            self::assertCount(1, $store->certificates());
        }
    }

    public function testRejectsUnauthorizedSignerAndShrunkStoreUnlessForced(): void
    {
        $pki = new TestPki();
        $authorized = $pki->issue(['CN' => 'Authorized test signer']);
        $unauthorized = $pki->issue(['CN' => 'Other test signer']);
        $ca1 = $pki->issue(['CN' => 'CA 1'], profile: 'ca');
        $ca2 = $pki->issue(['CN' => 'CA 2'], profile: 'ca');
        $store = new TrustStore($this->dir . '/trust');
        $options = new Options(lotlSignerFingerprints: [hash('sha256', TestPki::der($authorized['pem']))]);
        $importer = new TrustListImporter(new FakeTransport(), new XmlSignatureVerifier(), $store, $options);
        $xml = SignedLists::sign(SignedLists::tsl('ES', [$ca1['pem'], $ca2['pem']]), $authorized);
        self::assertSame(2, $importer->importTsl($xml, 'ES', $options->lotlSignerFingerprints)->count);
        $small = SignedLists::sign(SignedLists::tsl('ES', [$ca1['pem']]), $authorized);
        $dry = $importer->importTsl($xml, 'ES', $options->lotlSignerFingerprints, dryRun: true);
        self::assertSame([], $dry->removed);
        $shrunkPreview = $importer->importTsl($small, 'ES', $options->lotlSignerFingerprints, dryRun: true);
        self::assertTrue($shrunkPreview->retentionRejected);
        self::assertCount(1, $shrunkPreview->removed);
        try {
            $importer->importTsl($small, 'ES', $options->lotlSignerFingerprints);
            self::fail('The shrink safeguard should reject this update.');
        } catch (TrustListRejected) {
            self::assertCount(2, $store->certificates());
        }
        self::assertSame(1, $importer->importTsl($small, 'ES', $options->lotlSignerFingerprints, force: true)->count);
        $other = SignedLists::sign(SignedLists::tsl('ES', [$ca1['pem']]), $unauthorized);
        $this->expectException(TrustListRejected::class);
        $importer->importTsl($other, 'ES', $options->lotlSignerFingerprints);
    }

    public function testServiceHistorySelectsStateAtRequestedDate(): void
    {
        $pki = new TestPki();
        $signer = $pki->issue(['CN' => 'Signer']);
        $ca = $pki->issue(['CN' => 'Historical CA'], profile: 'ca');
        $xml = SignedLists::sign(SignedLists::tsl('ES', [$ca['pem']], 'withdrawn', true), $signer);
        $pins = [hash('sha256', TestPki::der($signer['pem']))];
        $importer = new TrustListImporter(new FakeTransport(), new XmlSignatureVerifier(), new TrustStore($this->dir . '/trust'), new Options());
        $old = $importer->importTsl($xml, 'ES', $pins, dryRun: true, at: new DateTimeImmutable('2024-01-01'));
        self::assertSame(1, $old->count);
        $this->expectException(TrustListRejected::class);
        $importer->importTsl($xml, 'ES', $pins, dryRun: true, at: new DateTimeImmutable('2026-01-01'));
    }

    public function testAcceptsRsaPssNationalSignatureAndRejectsTampering(): void
    {
        $pki = new TestPki();
        $signer = $pki->issue(['CN' => 'PSS test signer']);
        $ca = $pki->issue(['CN' => 'PSS test CA'], profile: 'ca');
        $xml = SignedLists::signPss(SignedLists::tsl('ES', [$ca['pem']]), $signer);
        $pins = [hash('sha256', TestPki::der($signer['pem']))];
        $importer = new TrustListImporter(new FakeTransport(), new XmlSignatureVerifier(), new TrustStore($this->dir . '/trust'), new Options());
        self::assertSame(1, $importer->importTsl($xml, 'ES', $pins, dryRun: true)->count);
        $this->expectException(TrustListRejected::class);
        $importer->importTsl(str_replace('granted', 'withdrawn', $xml), 'ES', $pins, dryRun: true);
    }
}
