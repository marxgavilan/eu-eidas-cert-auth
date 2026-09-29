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
        $qualified = is_string($qc) && (str_contains($qc, "\x06\x06\x04\x00\x8e\x46\x01\x01") || str_contains($qc, '0.4.0.1862.1.1'));

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
        );
    }

    /** @return list<string> */
    private static function urls(string $text, string $marker): array
    {
        preg_match_all('/' . preg_quote($marker, '/') . '\s*(https?:\/\/[^\s,]+)/i', $text, $matches);

        return array_values(array_unique($matches[1]));
    }
}
