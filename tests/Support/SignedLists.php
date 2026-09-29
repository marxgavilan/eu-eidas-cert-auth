<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Support;

use DOMDocument;
use DOMXPath;
use OpenSSLAsymmetricKey;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

final class SignedLists
{
    /** @param array{pem: string, key: OpenSSLAsymmetricKey} $signer */
    public static function sign(string $xml, array $signer): string
    {
        $document = new DOMDocument();
        $document->loadXML($xml, LIBXML_NONET);
        $signature = new XMLSecurityDSig();
        $signature->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $signature->addReference($document, XMLSecurityDSig::SHA256, ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N], ['force_uri' => true]);
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        openssl_pkey_export($signer['key'], $private);
        $key->loadKey($private);
        $signature->sign($key);
        $signature->add509Cert($signer['pem']);
        if ($document->documentElement === null) {
            throw new \RuntimeException('Invalid test XML.');
        }
        $signature->appendSignature($document->documentElement);

        return (string) $document->saveXML();
    }

    /** @param array{pem: string, key: OpenSSLAsymmetricKey} $signer */
    public static function signPss(string $xml, array $signer): string
    {
        $document = new DOMDocument();
        $document->loadXML(self::sign($xml, $signer), LIBXML_NONET);
        $xpath = new DOMXPath($document);
        $methods = $xpath->query('//*[local-name()="SignatureMethod"]');
        $values = $xpath->query('//*[local-name()="SignatureValue"]');
        $method = $methods === false ? null : $methods->item(0);
        $value = $values === false ? null : $values->item(0);
        if (! $method instanceof \DOMElement || ! $value instanceof \DOMElement) {
            throw new \RuntimeException('Invalid signed test XML.');
        }
        $method->setAttribute('Algorithm', 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1');
        $signature = new XMLSecurityDSig();
        $signature->locateSignature($document);
        $signedInfo = $signature->canonicalizeSignedInfo();
        $dir = sys_get_temp_dir() . '/eidas-pss-test-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        openssl_pkey_export($signer['key'], $private);
        file_put_contents($dir . '/key.pem', $private);
        file_put_contents($dir . '/info.bin', $signedInfo);
        try {
            $process = proc_open(['openssl', 'dgst', '-sha256', '-sign', $dir . '/key.pem', '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:-1', '-out', $dir . '/signature.bin', $dir . '/info.bin'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            if (! is_resource($process)) {
                throw new \RuntimeException('Cannot sign test PSS XML.');
            }
            foreach ($pipes as $pipe) {
                fclose($pipe);
            }
            if (proc_close($process) !== 0) {
                throw new \RuntimeException('Cannot sign test PSS XML.');
            }
            $value->textContent = base64_encode((string) file_get_contents($dir . '/signature.bin'));

            return (string) $document->saveXML();
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }

    public static function lotl(string $country, string $url, string $tslSignerPem): string
    {
        $cert = base64_encode(TestPki::der($tslSignerPem));

        return <<<XML
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><SchemeInformation><SchemeTerritory>EU</SchemeTerritory><TSLSequenceNumber>1</TSLSequenceNumber><ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate><PointersToOtherTSL><OtherTSLPointer><TSLLocation>{$url}</TSLLocation><ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>{$cert}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities><AdditionalInformation><OtherInformation><SchemeTerritory>{$country}</SchemeTerritory></OtherInformation></AdditionalInformation></OtherTSLPointer></PointersToOtherTSL></SchemeInformation></TrustServiceStatusList>
            XML;
    }

    /** @param list<string> $cas */
    public static function tsl(string $country, array $cas, string $status = 'granted', bool $history = false): string
    {
        $services = '';
        foreach ($cas as $pem) {
            $der = base64_encode(TestPki::der($pem));
            $past = $history ? '<ServiceHistory><ServiceHistoryInstance><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance></ServiceHistory>' : '';
            $services .= '<TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/' . $status . '</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime><ServiceDigitalIdentity><DigitalId><X509Certificate>' . $der . '</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceInformationExtensions><Extension><AdditionalServiceInformation><URI>http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</URI></AdditionalServiceInformation></Extension></ServiceInformationExtensions></ServiceInformation>' . $past . '</TSPService>';
        }

        return '<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><SchemeInformation><SchemeTerritory>' . $country . '</SchemeTerritory><TSLSequenceNumber>1</TSLSequenceNumber><ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation><TrustServiceProviderList><TrustServiceProvider><TSPServices>' . $services . '</TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>';
    }
}
