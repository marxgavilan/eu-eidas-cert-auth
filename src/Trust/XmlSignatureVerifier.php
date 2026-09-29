<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Trust;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use Iberfacil\EidasCertAuth\Exceptions\TrustListRejected;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Throwable;

final class XmlSignatureVerifier
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    private const EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    private const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    private const RSA_PSS_SHA256 = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';

    private const RSA_PSS_SHA384 = 'http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1';

    private const RSA_PSS_SHA512 = 'http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1';

    /**
     * @param list<string> $allowedFingerprints
     */
    public function verify(string $xml, array $allowedFingerprints): DOMDocument
    {
        if ($allowedFingerprints === [] || strlen($xml) > 20_000_000 || stripos($xml, '<!DOCTYPE') !== false) {
            throw new TrustListRejected('Unsigned, oversized or unsafe trusted list.');
        }
        $document = new DOMDocument();
        if (! @$document->loadXML($xml, LIBXML_NONET) || $document->doctype !== null || ! $document->documentElement instanceof DOMElement) {
            throw new TrustListRejected('Invalid trusted-list XML.');
        }
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('ds', self::DS);
        $signatures = $xpath->query('//ds:Signature');
        if ($signatures === false || $signatures->length !== 1) {
            throw new TrustListRejected('A trusted list must have exactly one XML signature.');
        }
        $root = $document->documentElement;
        $signatureNode = $signatures->item(0);
        if (! $signatureNode instanceof DOMElement || $signatureNode->parentNode !== $root) {
            throw new TrustListRejected('The signature must be enveloped in the document root.');
        }
        $canonical = self::first($xpath, './ds:SignedInfo/ds:CanonicalizationMethod', $signatureNode);
        if (! $canonical instanceof DOMElement || $canonical->getAttribute('Algorithm') !== self::EXCLUSIVE) {
            throw new TrustListRejected('Exclusive canonicalization is required.');
        }
        $method = self::first($xpath, './ds:SignedInfo/ds:SignatureMethod', $signatureNode);
        $signatureAlgorithm = $method?->getAttribute('Algorithm');
        if (! in_array($signatureAlgorithm, [XMLSecurityKey::RSA_SHA256, XMLSecurityKey::RSA_SHA384, XMLSecurityKey::RSA_SHA512, self::RSA_PSS_SHA256, self::RSA_PSS_SHA384, self::RSA_PSS_SHA512], true)) {
            throw new TrustListRejected('A SHA-2 XML signature is required.');
        }
        $references = $xpath->query('./ds:SignedInfo/ds:Reference', $signatureNode);
        if ($references === false || $references->length === 0) {
            throw new TrustListRejected('Missing signed references.');
        }
        $rootSigned = false;
        foreach ($references as $reference) {
            if (! $reference instanceof DOMElement) {
                throw new TrustListRejected('Invalid signed reference.');
            }
            $uri = $reference->getAttribute('URI');
            if ($uri !== '' && ! str_starts_with($uri, '#')) {
                throw new TrustListRejected('External signature references are forbidden.');
            }
            if ($uri !== '') {
                $id = substr($uri, 1);
                if ($id === '' || count(self::matchingIds($xpath, $id)) !== 1) {
                    throw new TrustListRejected('Ambiguous signature reference.');
                }
            }
            $algorithms = [];
            foreach ($xpath->query('./ds:Transforms/ds:Transform', $reference) ?: [] as $transform) {
                if ($transform instanceof DOMElement) {
                    $algorithms[] = $transform->getAttribute('Algorithm');
                }
            }
            if ($uri === '' || $root->getAttribute('Id') === substr($uri, 1)) {
                $rootSigned = in_array(self::ENVELOPED, $algorithms, true) && in_array(self::EXCLUSIVE, $algorithms, true);
            }
            foreach ($algorithms as $algorithm) {
                if (! in_array($algorithm, [self::ENVELOPED, self::EXCLUSIVE], true)) {
                    throw new TrustListRejected('Unsupported signature transform.');
                }
            }
            $digest = self::first($xpath, './ds:DigestMethod', $reference);
            if (! $digest instanceof DOMElement || ! in_array($digest->getAttribute('Algorithm'), [XMLSecurityDSig::SHA256, XMLSecurityDSig::SHA384, XMLSecurityDSig::SHA512], true)) {
                throw new TrustListRejected('A SHA-2 digest is required.');
            }
        }
        if (! $rootSigned) {
            throw new TrustListRejected('The document root is not signed.');
        }
        $certNode = self::first($xpath, './ds:KeyInfo/ds:X509Data/ds:X509Certificate', $signatureNode);
        $der = $certNode === null ? false : base64_decode(preg_replace('/\s+/', '', $certNode->textContent) ?? '', true);
        if (! is_string($der)) {
            throw new TrustListRejected('Missing signature certificate.');
        }
        $fingerprint = hash('sha256', $der);
        if (! in_array($fingerprint, array_map('strtolower', $allowedFingerprints), true)) {
            throw new TrustListRejected('The trusted-list signer is not authorized.');
        }
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
        $cert = @openssl_x509_parse($pem);
        if (! is_array($cert) || (int) ($cert['validFrom_time_t'] ?? 0) > time() || (int) ($cert['validTo_time_t'] ?? 0) < time()) {
            throw new TrustListRejected('The signature certificate is invalid or expired.');
        }
        $signedRootBytes = null;
        try {
            $signature = new XMLSecurityDSig();
            $signature->locateSignature($document);
            $signedInfo = $signature->canonicalizeSignedInfo();
            foreach ($references as $reference) {
                if (! $reference instanceof DOMElement) {
                    throw new TrustListRejected('Invalid signed reference.');
                }
                $uri = $reference->getAttribute('URI');
                if ($uri === '' || $root->getAttribute('Id') === substr($uri, 1)) {
                    $copy = clone $document;
                    $copyXpath = new DOMXPath($copy);
                    $copyXpath->registerNamespace('ds', self::DS);
                    $copySignature = self::first($copyXpath, '//ds:Signature');
                    if ($copySignature instanceof DOMNode && $copySignature->parentNode !== null) {
                        $copySignature->parentNode->removeChild($copySignature);
                    }
                    $canonicalData = $copy->documentElement?->C14N(true, false);
                } else {
                    $id = substr($uri, 1);
                    $target = self::matchingIds($xpath, $id)[0] ?? null;
                    $canonicalData = $target instanceof DOMElement ? $target->C14N(true, false) : false;
                }
                if (! is_string($canonicalData) || ! $signature->validateDigest($reference, $canonicalData)) {
                    throw new TrustListRejected('Signed content has changed.');
                }
                if ($uri === '' || $root->getAttribute('Id') === substr($uri, 1)) {
                    $signedRootBytes = $canonicalData;
                }
            }
            if (in_array($signatureAlgorithm, [self::RSA_PSS_SHA256, self::RSA_PSS_SHA384, self::RSA_PSS_SHA512], true)) {
                $valueNode = self::first($xpath, './ds:SignatureValue', $signatureNode);
                $value = $valueNode === null ? false : base64_decode(preg_replace('/\s+/', '', $valueNode->textContent) ?? '', true);
                if (! is_string($signedInfo) || ! is_string($value) || ! self::verifyPss($pem, $signedInfo, $value, $signatureAlgorithm)) {
                    throw new TrustListRejected('Invalid RSA-PSS XML signature.');
                }
            } else {
                $key = $signature->locateKey();
                if ($key === null) {
                    throw new TrustListRejected('Unsupported signature key.');
                }
                $key->loadKey($pem, false, true);
                if ($signature->verify($key) !== 1) {
                    throw new TrustListRejected('Invalid XML signature.');
                }
            }
        } catch (TrustListRejected $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new TrustListRejected('Invalid XML signature.', 0, $exception);
        }

        $signedDocument = new DOMDocument();
        if ($signedRootBytes === null || ! @$signedDocument->loadXML($signedRootBytes, LIBXML_NONET) || $signedDocument->doctype !== null) {
            throw new TrustListRejected('Cannot parse verified signed content.');
        }

        return $signedDocument;
    }

    private static function first(DOMXPath $xpath, string $query, ?DOMNode $context = null): ?DOMElement
    {
        $list = $xpath->query($query, $context);
        $node = $list === false ? null : $list->item(0);

        return $node instanceof DOMElement ? $node : null;
    }

    /** @return list<DOMElement> */
    private static function matchingIds(DOMXPath $xpath, string $id): array
    {
        $matches = [];
        foreach ($xpath->query('//*[@Id or @ID or @id]') ?: [] as $node) {
            if ($node instanceof DOMElement && ($node->getAttribute('Id') === $id || $node->getAttribute('ID') === $id || $node->getAttribute('id') === $id)) {
                $matches[] = $node;
            }
        }

        return $matches;
    }

    private static function verifyPss(string $certificate, string $signedInfo, string $signature, string $method): bool
    {
        $key = openssl_pkey_get_public($certificate);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if (! is_array($details) || ! is_string($details['key'] ?? null)) {
            return false;
        }
        $dir = sys_get_temp_dir() . '/eidas-pss-' . bin2hex(random_bytes(8));
        if (! mkdir($dir, 0700)) {
            return false;
        }
        try {
            file_put_contents($dir . '/public.pem', $details['key']);
            file_put_contents($dir . '/info.bin', $signedInfo);
            file_put_contents($dir . '/signature.bin', $signature);
            $digest = match ($method) {
                self::RSA_PSS_SHA256 => '-sha256',
                self::RSA_PSS_SHA384 => '-sha384',
                default => '-sha512',
            };
            $process = proc_open(['openssl', 'dgst', $digest, '-verify', $dir . '/public.pem', '-signature', $dir . '/signature.bin', '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:-2', $dir . '/info.bin'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            if (! is_resource($process)) {
                return false;
            }
            fclose($pipes[0]);
            stream_get_contents($pipes[1]);
            stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);

            return proc_close($process) === 0;
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($dir);
        }
    }
}
