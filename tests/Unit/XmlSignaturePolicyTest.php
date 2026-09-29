<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use DOMDocument;
use DOMXPath;
use Iberfacil\EidasCertAuth\Exceptions\TrustListRejected;
use Iberfacil\EidasCertAuth\Tests\Support\SignedLists;
use Iberfacil\EidasCertAuth\Tests\Support\TestPki;
use Iberfacil\EidasCertAuth\Trust\XmlSignatureVerifier;
use PHPUnit\Framework\TestCase;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

final class XmlSignaturePolicyTest extends TestCase
{
    public function testValidButForbiddenAlgorithmsTransformsAndNonRootReferenceAreRejected(): void
    {
        $pki = new TestPki();
        $signer = $pki->issue(['CN' => 'Signer']);
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $xml = SignedLists::tsl('ES', [$ca['pem']]);
        $pins = [hash('sha256', TestPki::der($signer['pem']))];
        $enveloped = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
        $cases = [
            [XMLSecurityKey::RSA_SHA1, XMLSecurityDSig::SHA256, [$enveloped, XMLSecurityDSig::EXC_C14N], false],
            [XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA1, [$enveloped, XMLSecurityDSig::EXC_C14N], false],
            [XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA256, [$enveloped, XMLSecurityDSig::C14N], false],
            [XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA256, [XMLSecurityDSig::EXC_C14N], true],
        ];
        $rejected = 0;
        foreach ($cases as [$method, $digest, $transforms, $child]) {
            $signed = self::signWith($xml, $signer, $method, $digest, $transforms, $child);
            try {
                (new XmlSignatureVerifier())->verify($signed, $pins);
                self::fail('A forbidden but correctly signed XML signature was accepted.');
            } catch (TrustListRejected) {
                $rejected++;
            }
        }
        self::assertCount($rejected, $cases);
    }

    public function testDuplicateIdMultipleSignatureAndExternalUriAreRejected(): void
    {
        $pki = new TestPki();
        $signer = $pki->issue(['CN' => 'Signer']);
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $signed = SignedLists::sign(SignedLists::tsl('ES', [$ca['pem']]), $signer);
        $pins = [hash('sha256', TestPki::der($signer['pem']))];
        $document = new DOMDocument();
        $document->loadXML($signed);
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $nodes = $xpath->query('//ds:Signature');
        $signature = $nodes === false ? null : $nodes->item(0);
        self::assertInstanceOf(\DOMNode::class, $signature);
        $multiple = str_replace('</ds:Signature>', '</ds:Signature>' . $document->saveXML($signature), $signed);
        $duplicates = str_replace('<SchemeInformation>', '<SchemeInformation Id="duplicate">', str_replace('<TrustServiceStatusList ', '<TrustServiceStatusList Id="duplicate" ', $signed));
        $external = str_replace('URI=""', 'URI="https://evil.example.test/x"', $signed);
        foreach ([$multiple, $duplicates, $external] as $candidate) {
            $this->expectRejected((string) $candidate, $pins);
        }
        $rootId = self::signWith(SignedLists::tsl('ES', [$ca['pem']]), $signer, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA256, ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N], false, true);
        self::assertStringContainsString('URI="#same"', $rootId);
        $this->expectRejected(str_replace('<SchemeInformation>', '<SchemeInformation Id="same">', $rootId), $pins);
    }

    public function testExpiredPinnedSignerIsRejected(): void
    {
        $pki = new TestPki();
        $signer = $pki->issue(['CN' => 'Signer'], days: 0);
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $signed = SignedLists::sign(SignedLists::tsl('ES', [$ca['pem']]), $signer);
        usleep(1_100_000);
        $this->expectException(TrustListRejected::class);
        (new XmlSignatureVerifier())->verify($signed, [hash('sha256', TestPki::der($signer['pem']))]);
    }

    /** @param list<string> $pins */
    private function expectRejected(string $xml, array $pins): void
    {
        try {
            (new XmlSignatureVerifier())->verify($xml, $pins);
            self::fail('Invalid XML signature was accepted.');
        } catch (TrustListRejected) {
        }
    }

    /**
     * @param array{pem: string, key: \OpenSSLAsymmetricKey} $signer
     * @param list<string> $transforms
     */
    private static function signWith(string $xml, array $signer, string $method, string $digest, array $transforms, bool $child, bool $rootId = false): string
    {
        $document = new DOMDocument();
        $document->loadXML($xml);
        $signature = new XMLSecurityDSig();
        $signature->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $nodes = (new DOMXPath($document))->query('//*[local-name()="SchemeInformation"]');
        $node = $rootId ? $document->documentElement : ($child && $nodes !== false ? $nodes->item(0) : $document);
        if (($child || $rootId) && $node instanceof \DOMElement) {
            $node->setAttribute('Id', $rootId ? 'same' : 'child');
        }
        if (! $node instanceof \DOMNode || ! $document->documentElement instanceof \DOMElement) {
            throw new \RuntimeException('Invalid test document.');
        }
        (new \ReflectionMethod($signature, 'addReference'))->invoke($signature, $node, $digest, $transforms, ($child || $rootId) ? ['id_name' => 'Id', 'overwrite' => false] : ['force_uri' => true]);
        $key = new XMLSecurityKey($method, ['type' => 'private']);
        openssl_pkey_export($signer['key'], $private);
        $key->loadKey($private);
        $signature->sign($key);
        $signature->add509Cert($signer['pem']);
        $signature->appendSignature($document->documentElement);

        return (string) $document->saveXML();
    }
}
