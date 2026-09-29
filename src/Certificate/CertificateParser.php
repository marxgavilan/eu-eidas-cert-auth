<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Certificate;

use DateTimeImmutable;
use Iberfacil\EidasCertAuth\Data\ParsedCertificate;

final class CertificateParser
{
    public static function normalizePem(string $raw): ?string
    {
        $raw = trim(str_contains($raw, '%') ? rawurldecode($raw) : $raw);
        if (! preg_match('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $raw, $match)) {
            return null;
        }
        $base64 = preg_replace('/\s+/', '', $match[1]);
        $der = is_string($base64) ? base64_decode($base64, true) : false;

        return is_string($der) ? "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n" : null;
    }

    public function parse(string $raw): ?ParsedCertificate
    {
        $pem = self::normalizePem($raw);
        $details = $pem === null ? false : @openssl_x509_parse($pem);
        if (! is_array($details) || ! is_array($details['subject'] ?? null) || ! is_array($details['issuer'] ?? null)) {
            return null;
        }
        $extensions = is_array($details['extensions'] ?? null) ? $details['extensions'] : [];
        $qc = $extensions['qcStatements'] ?? '';
        $qualified = is_string($qc) && self::hasQcCompliance($qc);

        return new ParsedCertificate(
            $pem,
            strtolower((string) openssl_x509_fingerprint($pem, 'sha256')),
            $details['subject'],
            $details['issuer'],
            (new DateTimeImmutable())->setTimestamp((int) ($details['validFrom_time_t'] ?? 0)),
            (new DateTimeImmutable())->setTimestamp((int) ($details['validTo_time_t'] ?? 0)),
            isset($extensions['keyUsage']) ? (string) $extensions['keyUsage'] : null,
            isset($extensions['extendedKeyUsage']) ? (string) $extensions['extendedKeyUsage'] : null,
            $qualified,
            self::urls((string) ($extensions['authorityInfoAccess'] ?? ''), 'OCSP - URI:'),
            self::urls((string) ($extensions['crlDistributionPoints'] ?? ''), 'URI:'),
            self::urls((string) ($extensions['authorityInfoAccess'] ?? ''), 'CA Issuers - URI:'),
        );
    }

    private static function hasQcCompliance(string $der): bool
    {
        $offset = 0;
        $outer = self::readTlv($der, $offset);
        if ($outer === null || $outer['tag'] !== 0x30 || $offset !== strlen($der)) {
            return false;
        }
        $statements = $outer['value'];
        $offset = 0;
        while ($offset < strlen($statements)) {
            $statement = self::readTlv($statements, $offset);
            if ($statement === null || $statement['tag'] !== 0x30) {
                return false;
            }
            $innerOffset = 0;
            $oid = self::readTlv($statement['value'], $innerOffset);
            if ($oid !== null && $oid['tag'] === 0x06 && $oid['value'] === "\x04\x00\x8e\x46\x01\x01") {
                return true;
            }
        }

        return false;
    }

    /** @return array{tag: int, value: string}|null */
    private static function readTlv(string $der, int &$offset): ?array
    {
        if ($offset + 2 > strlen($der)) {
            return null;
        }
        $tag = ord($der[$offset++]);
        $length = ord($der[$offset++]);
        if ($length & 0x80) {
            $bytes = $length & 0x7f;
            if ($bytes === 0 || $bytes > 4 || $offset + $bytes > strlen($der)) {
                return null;
            }
            $length = 0;
            for ($i = 0; $i < $bytes; $i++) {
                $length = ($length << 8) | ord($der[$offset++]);
            }
        }
        if ($offset + $length > strlen($der)) {
            return null;
        }
        $value = substr($der, $offset, $length);
        $offset += $length;

        return ['tag' => $tag, 'value' => $value];
    }

    /** @return list<string> */
    private static function urls(string $text, string $marker): array
    {
        preg_match_all('/' . preg_quote($marker, '/') . '\s*(https?:\/\/[^\s,]+)/i', $text, $matches);

        return array_values(array_unique($matches[1]));
    }
}
