<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Certificate;

use DateTimeImmutable;
use Iberfacil\EidasCertAuth\Contracts\IdentityExtractor;
use Iberfacil\EidasCertAuth\Contracts\Transport;
use Iberfacil\EidasCertAuth\Data\ParsedCertificate;
use Iberfacil\EidasCertAuth\Data\ValidationResult;
use Iberfacil\EidasCertAuth\Identity\FrenchIdentityExtractor;
use Iberfacil\EidasCertAuth\Identity\GenericIdentityExtractor;
use Iberfacil\EidasCertAuth\Identity\GermanIdentityExtractor;
use Iberfacil\EidasCertAuth\Identity\ItalianIdentityExtractor;
use Iberfacil\EidasCertAuth\Identity\PortugueseIdentityExtractor;
use Iberfacil\EidasCertAuth\Identity\SpanishIdentityExtractor;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Transport\CurlTransport;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use Throwable;

final class CertificateValidator
{
    /** @var array<string, array{pem: string, expires: int}> */
    private array $aiaCache = [];

    /**
     * @param list<IdentityExtractor> $extractors
     * @param list<string> $intermediates
     */
    public function __construct(private readonly CertificateParser $parser, private readonly TrustStore $store, private readonly RevocationChecker $revocation, private readonly Options $options, private readonly array $extractors = [], private readonly array $intermediates = [], private readonly ?Transport $aiaTransport = null) {}

    public function validate(string $raw, ?DateTimeImmutable $at = null): ValidationResult
    {
        $at ??= new DateTimeImmutable();
        $parsed = $this->parser->parse($raw);
        if ($parsed === null) {
            return ValidationResult::reject('malformed');
        }
        if ($parsed->notBefore > $at->modify('+5 minutes')) {
            return ValidationResult::reject('not_yet_valid', $parsed);
        }
        if ($parsed->notAfter <= $at) {
            return ValidationResult::reject('expired', $parsed);
        }
        $leafDetails = @openssl_x509_parse($parsed->pem);
        if (! is_array($leafDetails) || self::weakSignature($leafDetails)) {
            return ValidationResult::reject('untrusted', $parsed);
        }
        $issuer = $this->issuer($parsed, $at);
        if ($issuer === null) {
            return ValidationResult::reject('untrusted', $parsed);
        }
        if ($parsed->keyUsage === null || ! str_contains($parsed->keyUsage, 'Digital Signature') || ($parsed->extendedKeyUsage !== null && ! preg_match('/(?:^|,\s*)(?:TLS Web Client Authentication|clientAuth)(?:,|$)/', $parsed->extendedKeyUsage))) {
            return ValidationResult::reject('not_for_authentication', $parsed);
        }
        $anchorMetadata = $this->store->manifest()[$issuer['anchor']] ?? [];
        $qualificationRules = $anchorMetadata['not_qualified_criteria'] ?? [];
        $subjectCountry = strtoupper((string) ($parsed->subject['C'] ?? ''));
        $generic = (new GenericIdentityExtractor())->extract($parsed);
        $country = $generic->country !== '' ? $generic->country : $subjectCountry;
        if (! in_array($country, $this->options->acceptedCountries(), true)) {
            return ValidationResult::reject('country_not_accepted', $parsed);
        }
        if ($this->options->requireQualified && (QualificationCriteria::excludes($parsed->pem, $qualificationRules) || (! $parsed->qualified && ! $this->matchesAuthenticationPolicy($parsed, $country, $anchorMetadata)))) {
            return ValidationResult::reject('not_qualified', $parsed);
        }
        $extractors = $this->extractors === [] ? [new SpanishIdentityExtractor(), new PortugueseIdentityExtractor(), new ItalianIdentityExtractor(), new FrenchIdentityExtractor(), new GermanIdentityExtractor(), new GenericIdentityExtractor()] : $this->extractors;
        foreach ($extractors as $extractor) {
            if ($extractor->supports($country)) {
                $identity = $extractor->extract($parsed);
                break;
            }
        }
        if (! isset($identity) || $identity->identifier === null || $identity->personType === 'legal') {
            return ValidationResult::reject('no_personal_identity', $parsed);
        }
        $revocation = $this->revocation->check($parsed, $issuer['pem']);
        if ($revocation['status'] === 'revoked') {
            return ValidationResult::reject('revoked', $parsed);
        }
        if ($revocation['status'] !== 'good' && ! $this->options->softFailRevocation) {
            return ValidationResult::reject('revocation_unavailable', $parsed);
        }

        return new ValidationResult(true, null, $identity, $parsed, $revocation['source']);
    }

    /** @return array{pem: string, anchor: string}|null */
    private function issuer(ParsedCertificate $certificate, DateTimeImmutable $at): ?array
    {
        $anchors = $this->store->certificates();
        $pool = $this->intermediates;
        $current = $certificate->pem;
        $direct = null;
        for ($depth = 0; $depth < 5; $depth++) {
            foreach ($anchors as $fingerprint => $anchor) {
                if (self::signedBy($current, $anchor, $at, $depth)) {
                    return ['pem' => $direct ?? $anchor, 'anchor' => $fingerprint];
                }
            }
            $next = null;
            foreach ($pool as $pem) {
                if (self::signedBy($current, $pem, $at, $depth)) {
                    $next = $pem;
                    break;
                }
            }
            $next ??= $this->aiaIssuer($current, $at);
            if ($next === null || $next === $current) {
                return null;
            }
            $direct ??= $next;
            $current = $next;
        }

        return null;
    }

    /** @param array<string, mixed> $anchorMetadata */
    private function matchesAuthenticationPolicy(ParsedCertificate $certificate, string $country, array $anchorMetadata): bool
    {
        if (($anchorMetadata['country'] ?? null) !== $country || ($anchorMetadata['service'] ?? null) !== 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC' || ($anchorMetadata['fore_signatures'] ?? false) !== true) {
            return false;
        }
        $details = @openssl_x509_parse($certificate->pem);
        $policies = is_array($details) ? ($details['extensions']['certificatePolicies'] ?? null) : null;
        if (! is_string($policies)) {
            return false;
        }
        foreach ($this->options->authenticationPolicies[$country] ?? [] as $oid) {
            // Only the DNIe policy has a documented two-component version suffix.
            $version = $country === 'ES' && $oid === Options::DEFAULT_AUTHENTICATION_POLICIES['ES'][0] ? '(?:\.\d+\.\d+)?' : '';
            if (preg_match('/(?:^|\n)\s*Policy:\s*' . preg_quote($oid, '/') . $version . '(?=\s|$)/', $policies)) {
                return true;
            }
        }

        return false;
    }

    private function aiaIssuer(string $child, DateTimeImmutable $at): ?string
    {
        $parsed = $this->parser->parse($child);
        if ($parsed === null) {
            return null;
        }
        foreach (array_slice($parsed->caIssuerUrls, 0, 3) as $url) {
            $cached = $this->aiaCache[$url] ?? null;
            if ($cached !== null && $cached['expires'] > time()) {
                $pem = $cached['pem'];
            } else {
                try {
                    $body = ($this->aiaTransport ?? new CurlTransport(true))->get($url, $this->options->timeoutSeconds);
                } catch (Throwable) {
                    continue;
                }
                if (strlen($body) > 1_000_000) {
                    continue;
                }
                $pem = $this->parser->normalizePem($body) ?? $this->parser->normalizePem("-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($body), 64, "\n") . "-----END CERTIFICATE-----\n");
                if ($pem === null || @openssl_x509_parse($pem) === false) {
                    continue;
                }
                $this->aiaCache[$url] = ['pem' => $pem, 'expires' => time() + 3600];
            }
            if (self::signedBy($child, $pem, $at, 0)) {
                return $pem;
            }
        }

        return null;
    }

    private static function signedBy(string $child, string $issuer, DateTimeImmutable $at, int $depth): bool
    {
        $c = @openssl_x509_parse($child);
        $i = @openssl_x509_parse($issuer);
        if (! is_array($c) || ! is_array($i) || ($c['issuer'] ?? null) != ($i['subject'] ?? null) || ! str_contains((string) ($i['extensions']['basicConstraints'] ?? ''), 'CA:TRUE') || ! str_contains((string) ($i['extensions']['keyUsage'] ?? ''), 'Certificate Sign') || self::weakSignature($c) || self::weakSignature($i) || (int) ($i['validFrom_time_t'] ?? 0) > $at->getTimestamp() || (int) ($i['validTo_time_t'] ?? 0) < $at->getTimestamp()) {
            return false;
        }
        if (preg_match('/pathlen:(\d+)/i', (string) ($i['extensions']['basicConstraints'] ?? ''), $match) && $depth > (int) $match[1]) {
            return false;
        }
        $key = @openssl_pkey_get_public($issuer);

        return $key !== false && @openssl_x509_verify($child, $key) === 1;
    }

    /** @param array<string, mixed> $details */
    private static function weakSignature(array $details): bool
    {
        return preg_match('/(?:md5|sha1)/i', (string) ($details['signatureTypeSN'] ?? '')) === 1;
    }
}
