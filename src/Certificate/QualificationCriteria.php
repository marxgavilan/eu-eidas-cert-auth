<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Certificate;

use DOMDocument;
use DOMElement;

final class QualificationCriteria
{
    private const KEY_USAGE_NAMES = [
        'digitalSignature' => 'Digital Signature',
        'nonRepudiation' => 'Non Repudiation',
        'keyEncipherment' => 'Key Encipherment',
        'dataEncipherment' => 'Data Encipherment',
        'keyAgreement' => 'Key Agreement',
        'keyCertSign' => 'Certificate Sign',
        'crlSign' => 'CRL Sign',
        'encipherOnly' => 'Encipher Only',
        'decipherOnly' => 'Decipher Only',
    ];

    /** @param list<string> $rules */
    public static function excludes(string $certificatePem, array $rules): bool
    {
        if ($rules === []) {
            return false;
        }
        $details = @openssl_x509_parse($certificatePem);
        if (! is_array($details)) {
            return true;
        }
        foreach ($rules as $xml) {
            $document = new DOMDocument();
            if (! @$document->loadXML($xml, LIBXML_NONET) || $document->doctype !== null) {
                return true;
            }
            $root = $document->documentElement;
            $criteria = $root instanceof DOMElement ? self::children($root)[0] ?? null : null;
            if (! $criteria instanceof DOMElement || $criteria->localName !== 'CriteriaList' || self::matches($criteria, $details) !== false) {
                return true;
            }
        }

        return false;
    }

    /** @param array<string, mixed> $details */
    private static function matches(DOMElement $criteria, array $details): ?bool
    {
        $results = [];
        foreach (self::children($criteria) as $child) {
            $results[] = match ($child->localName) {
                'KeyUsage' => self::keyUsageMatches($child, $details),
                'PolicySet' => self::policyMatches($child, $details),
                'CriteriaList' => self::matches($child, $details),
                'Description' => 'description',
                default => null,
            };
        }
        $results = array_values(array_filter($results, static fn(bool|string|null $result): bool => $result !== 'description'));
        if (in_array(null, $results, true)) {
            return null;
        }
        if ($results === []) {
            return null;
        }

        return match ($criteria->getAttribute('assert')) {
            'all' => ! in_array(false, $results, true),
            'atLeastOne' => in_array(true, $results, true),
            'none' => ! in_array(true, $results, true),
            default => null,
        };
    }

    /** @param array<string, mixed> $details */
    private static function keyUsageMatches(DOMElement $element, array $details): ?bool
    {
        $usage = $details['extensions']['keyUsage'] ?? null;
        if (! is_string($usage)) {
            return false;
        }
        $bits = array_map('trim', explode(',', $usage));
        $seen = false;
        foreach (self::children($element) as $bit) {
            if ($bit->localName !== 'KeyUsageBit' || ! isset(self::KEY_USAGE_NAMES[$bit->getAttribute('name')]) || ! in_array(trim($bit->textContent), ['true', 'false', '1', '0'], true)) {
                return null;
            }
            $seen = true;
            $expected = in_array(trim($bit->textContent), ['true', '1'], true);
            if (in_array(self::KEY_USAGE_NAMES[$bit->getAttribute('name')], $bits, true) !== $expected) {
                return false;
            }
        }

        return $seen ? true : null;
    }

    /** @param array<string, mixed> $details */
    private static function policyMatches(DOMElement $element, array $details): ?bool
    {
        $policies = $details['extensions']['certificatePolicies'] ?? null;
        if (! is_string($policies)) {
            return false;
        }
        $seen = false;
        foreach ($element->getElementsByTagNameNS('*', 'Identifier') as $identifier) {
            $oid = trim($identifier->textContent);
            if (! preg_match('/^\d+(?:\.\d+)+$/', $oid)) {
                return null;
            }
            $seen = true;
            if (! preg_match('/(?<![\d.])' . preg_quote($oid, '/') . '(?![\d.])/', $policies)) {
                return false;
            }
        }

        return $seen ? true : null;
    }

    /** @return list<DOMElement> */
    private static function children(DOMElement $parent): array
    {
        $result = [];
        foreach ($parent->childNodes as $child) {
            if ($child instanceof DOMElement) {
                $result[] = $child;
            }
        }

        return $result;
    }
}
