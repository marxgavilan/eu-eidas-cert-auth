<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use Iberfacil\EidasCertAuth\Exceptions\TrustListRejected;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Tests\Support\SignedLists;
use Iberfacil\EidasCertAuth\Tests\Support\TestPki;
use Iberfacil\EidasCertAuth\Transport\FakeTransport;
use Iberfacil\EidasCertAuth\Trust\TrustListImporter;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use Iberfacil\EidasCertAuth\Trust\XmlSignatureVerifier;
use PHPUnit\Framework\TestCase;

final class LotlPolicyTest extends TestCase
{
    public function testWrongNationalSignerTerritoryAndMissingCountryAreRejected(): void
    {
        $pki = new TestPki();
        $lotlSigner = $pki->issue(['CN' => 'LOTL']);
        $esSigner = $pki->issue(['CN' => 'ES signer']);
        $ptSigner = $pki->issue(['CN' => 'PT signer']);
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $url = 'https://lists.example.test/es.xml';
        $lotl = SignedLists::sign(SignedLists::lotl('ES', $url, $esSigner['pem']), $lotlSigner);
        $options = new Options(lotlSignerFingerprints: [hash('sha256', TestPki::der($lotlSigner['pem']))]);
        foreach ([
            SignedLists::sign(SignedLists::tsl('ES', [$ca['pem']]), $ptSigner),
            SignedLists::sign(SignedLists::tsl('PT', [$ca['pem']]), $esSigner),
        ] as $national) {
            $transport = (new FakeTransport())->respond($url, $national);
            $importer = new TrustListImporter($transport, new XmlSignatureVerifier(), new TrustStore(sys_get_temp_dir() . '/missing-eidas-lotl-' . bin2hex(random_bytes(4))), $options);
            try {
                $importer->importLotl($lotl);
                self::fail('Wrong national TSL accepted.');
            } catch (TrustListRejected) {
            }
        }
        $missingOptions = new Options(countries: ['ES', 'PT'], lotlSignerFingerprints: $options->lotlSignerFingerprints);
        $transport = (new FakeTransport())->respond($url, SignedLists::sign(SignedLists::tsl('ES', [$ca['pem']]), $esSigner));
        $importer = new TrustListImporter($transport, new XmlSignatureVerifier(), new TrustStore(sys_get_temp_dir() . '/missing-eidas-lotl-' . bin2hex(random_bytes(4))), $missingOptions);
        $this->expectException(TrustListRejected::class);
        $importer->importLotl($lotl);
    }

    public function testUnsafeDuplicateAndPdfPointersAreRejectedOrSkipped(): void
    {
        $pki = new TestPki();
        $lotlSigner = $pki->issue(['CN' => 'LOTL']);
        $esSigner = $pki->issue(['CN' => 'ES signer']);
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $url = 'https://lists.example.test/es.xml';
        $raw = SignedLists::lotl('ES', $url, $esSigner['pem']);
        $options = new Options(lotlSignerFingerprints: [hash('sha256', TestPki::der($lotlSigner['pem']))]);
        $transport = (new FakeTransport())->respond($url, SignedLists::sign(SignedLists::tsl('ES', [$ca['pem']]), $esSigner));
        $importer = new TrustListImporter($transport, new XmlSignatureVerifier(), new TrustStore(sys_get_temp_dir() . '/missing-eidas-lotl-' . bin2hex(random_bytes(4))), $options);
        $start = strpos($raw, '<OtherTSLPointer>');
        $end = strpos($raw, '</OtherTSLPointer>');
        self::assertIsInt($start);
        self::assertIsInt($end);
        $pointer = substr($raw, $start, $end - $start + strlen('</OtherTSLPointer>'));
        foreach ([
            str_replace('https://', 'http://', $raw),
            str_replace('</PointersToOtherTSL>', $pointer . '</PointersToOtherTSL>', $raw),
            str_replace('</OtherTSLPointer>', '<AdditionalInformation><OtherInformation><MimeType>application/pdf</MimeType></OtherInformation></AdditionalInformation></OtherTSLPointer>', $raw),
        ] as $candidate) {
            try {
                $importer->importLotl(SignedLists::sign($candidate, $lotlSigner));
                self::fail('Unsafe LOTL pointer accepted.');
            } catch (TrustListRejected) {
            }
        }
    }
    public function testExpiredMissingNextUpdateAndMissingSequenceAreRejected(): void
    {
        $pki = new TestPki();
        $signer = $pki->issue(['CN' => 'LOTL']);
        $nationalSigner = $pki->issue(['CN' => 'National']);
        $url = 'https://lists.example.test/es.xml';
        $raw = SignedLists::lotl('ES', $url, $nationalSigner['pem']);
        $options = new Options(lotlSignerFingerprints: [hash('sha256', TestPki::der($signer['pem']))]);
        $importer = new TrustListImporter(new FakeTransport(), new XmlSignatureVerifier(), new TrustStore(sys_get_temp_dir() . '/missing-eidas-lotl-' . bin2hex(random_bytes(4))), $options);
        $rejected = 0;
        foreach ([
            str_replace('2099-01-01', '2020-01-01', $raw),
            preg_replace('#<NextUpdate>.*?</NextUpdate>#', '', $raw),
            str_replace('<TSLSequenceNumber>1</TSLSequenceNumber>', '', $raw),
        ] as $candidate) {
            try {
                $importer->importLotl(SignedLists::sign((string) $candidate, $signer));
                self::fail('Unfresh LOTL was accepted.');
            } catch (TrustListRejected) {
                $rejected++;
            }
        }
        self::assertSame(3, $rejected);
    }

}
