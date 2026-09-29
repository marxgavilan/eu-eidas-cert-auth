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
use Psr\SimpleCache\CacheInterface;
use Throwable;

final class CertificateValidator
{
    /** @var array<string, array{der: string, expires: int}> */
    private array $aiaCache = [];

    /**
     * @param list<IdentityExtractor> $extractors
     * @param list<string> $intermediates
     */
    public function __construct(private readonly CertificateParser $parser, private readonly TrustStore $store, private readonly RevocationChecker $revocation, private readonly Options $options, private readonly array $extractors = [], private readonly array $intermediates = [], private readonly ?Transport $aiaTransport = null, private readonly ?CacheInterface $aiaCacheStore = null) {}

    public function profile(string $name): \Iberfacil\EidasCertAuth\ValidationProfile
    {
        return $this->options->profile($name);
    }

    public function validate(string $raw, ?DateTimeImmutable $at = null, string $profile = 'default'): ValidationResult
    {
        $policy = $this->options->profile($profile);
        $at ??= new DateTimeImmutable();
        $parsed = $this->parser->parse($raw);
        if ($parsed === null) {
            return ValidationResult::reject('malformed', profile: $profile);
        }
        if ($parsed->notBefore > $at->modify('+5 minutes')) {
            return ValidationResult::reject('not_yet_valid', $parsed, $profile);
        }
        if ($parsed->notAfter <= $at) {
            return ValidationResult::reject('expired', $parsed, $profile);
        }
        $leafDetails = @openssl_x509_parse($parsed->pem);
        if (! is_array($leafDetails) || self::weakSignature($leafDetails)) {
            return ValidationResult::reject('untrusted', $parsed, $profile);
        }
        $issuer = $this->issuer($parsed, $at, $policy->aiaFetch);
        if ($issuer === null) {
            return ValidationResult::reject('untrusted', $parsed, $profile);
        }
        if ($parsed->extendedKeyUsage !== null ? ! preg_match('/(?:^|,\s*)(?:TLS Web Client Authentication|clientAuth)(?:,|$)/', $parsed->extendedKeyUsage) : ($parsed->keyUsage === null || ! str_contains($parsed->keyUsage, 'Digital Signature'))) {
            return ValidationResult::reject('no_authentication_usage', $parsed, $profile);
        }
        $anchorMetadata = $this->store->manifest()[$issuer['anchor']] ?? [];
        $qualificationRules = $anchorMetadata['not_qualified_criteria'] ?? [];
        $subjectCountry = strtoupper((string) ($parsed->subject['C'] ?? ''));
        $generic = (new GenericIdentityExtractor())->extract($parsed);
        $country = $generic->country !== '' ? $generic->country : $subjectCountry;
        if (! in_array($country, $policy->countries, true)) {
            return ValidationResult::reject('country_not_accepted', $parsed, $profile);
        }
        if (! $parsed->qualified && (($anchorMetadata['country'] ?? null) !== $country || ($anchorMetadata['service'] ?? null) !== 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC' || ($anchorMetadata['fore_signatures'] ?? false) !== true)) {
            return ValidationResult::reject('untrusted', $parsed, $profile);
        }
        if ($this->isDnieAnchor($issuer['anchor']) && ! $policy->dnie) {
            return ValidationResult::reject('dnie_disabled_for_profile', $parsed, $profile);
        }
        if ($policy->qualifiedRequired && (! $parsed->qualified || QualificationCriteria::excludes($parsed->pem, $qualificationRules))) {
            return ValidationResult::reject('qualified_required', $parsed, $profile);
        }
        if (isset($policy->authenticationPolicies[$country]) && ! $this->matchesAuthenticationPolicy($parsed, $country, $policy->authenticationPolicies[$country])) {
            return ValidationResult::reject('authentication_policy_mismatch', $parsed, $profile);
        }
        $extractors = $this->extractors === [] ? [new SpanishIdentityExtractor(), new PortugueseIdentityExtractor(), new ItalianIdentityExtractor(), new FrenchIdentityExtractor(), new GermanIdentityExtractor(), new GenericIdentityExtractor()] : $this->extractors;
        foreach ($extractors as $extractor) {
            if ($extractor->supports($country)) {
                $identity = $extractor->extract($parsed);
                break;
            }
        }
        if (! isset($identity) || ($identity->personType === 'legal' ? $identity->organizationIdentifier === null : $identity->identifier === null)) {
            return ValidationResult::reject('no_personal_identity', $parsed, $profile);
        }
        if (! in_array($identity->personType, $policy->personTypes, true)) {
            return ValidationResult::reject('person_type_not_allowed', $parsed, $profile);
        }
        $revocation = $this->revocation->check($parsed, $issuer['pem']);
        if ($revocation['status'] === 'revoked') {
            return ValidationResult::reject('revoked', $parsed, $profile);
        }
        if ($revocation['status'] !== 'good' && ! $policy->softFailRevocation) {
            return ValidationResult::reject('revocation_unavailable', $parsed, $profile);
        }

        return new ValidationResult(true, null, $identity, $parsed, $revocation['source'], $profile);
    }

    /** @return array{pem: string, anchor: string}|null */
    private function issuer(ParsedCertificate $certificate, DateTimeImmutable $at, bool $aiaFetch): ?array
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
            if ($next === null && $depth === 0 && $aiaFetch) {
                $next = $this->aiaIssuer($certificate, $anchors, $at, $depth);
            }
            if ($next === null || $next === $current) {
                return null;
            }
            $direct ??= $next;
            $current = $next;
        }

        return null;
    }

    /** @param list<string> $accepted */
    private function matchesAuthenticationPolicy(ParsedCertificate $certificate, string $country, array $accepted): bool
    {
        $details = @openssl_x509_parse($certificate->pem);
        $policies = is_array($details) ? ($details['extensions']['certificatePolicies'] ?? null) : null;
        if (! is_string($policies)) {
            return false;
        }
        foreach ($accepted as $oid) {
            // Only the DNIe policy has a documented two-component version suffix.
            $version = $country === 'ES' && $oid === '2.16.724.1.2.2.2.4' ? '(?:\.\d+\.\d+)?' : '';
            if (preg_match('/(?:^|\n)\s*Policy:\s*' . preg_quote($oid, '/') . $version . '(?=\s|$)/', $policies)) {
                return true;
            }
        }

        return false;
    }

    private function isDnieAnchor(string $fingerprint): bool
    {
        $pem = $this->store->certificates()[$fingerprint] ?? null;
        $details = is_string($pem) ? @openssl_x509_parse($pem) : false;
        $subject = is_array($details) ? ($details['subject'] ?? []) : [];
        $name = is_array($subject) ? ($subject['CN'] ?? '') : '';

        return is_string($name) && preg_match('/\bDNIE\b/i', $name) === 1;
    }

    /** @param array<string, string> $anchors */
    private function aiaIssuer(ParsedCertificate $child, array $anchors, DateTimeImmutable $at, int $depth): ?string
    {
        if ($child->issuer === $child->subject || $child->caIssuerUrls === [] || $anchors === []) {
            return null;
        }
        $childDetails = @openssl_x509_parse($child->pem);
        $authorityKey = is_array($childDetails) ? self::keyIdentifier($childDetails['extensions']['authorityKeyIdentifier'] ?? null) : null;
        foreach ($anchors as $anchor) {
            $details = @openssl_x509_parse($anchor);
            if (is_array($details) && ($child->issuer === ($details['subject'] ?? null) || ($authorityKey !== null && $authorityKey === self::keyIdentifier($details['extensions']['subjectKeyIdentifier'] ?? null)))) {
                return null;
            }
        }

        $url = $child->caIssuerUrls[0];
        $host = parse_url($url, PHP_URL_HOST);
        if (! is_string($host) || ($this->options->aiaAllowedHosts !== [] && ! in_array(strtolower($host), $this->options->aiaAllowedHosts, true))) {
            return null;
        }
        $key = 'eidas:aia:' . hash('sha256', $url);
        try {
            $der = $this->aiaCacheStore?->get($key);
        } catch (Throwable) {
            $der = null;
        }
        if (! is_string($der)) {
            $cached = $this->aiaCache[$key] ?? null;
            $der = $cached !== null && $cached['expires'] > time() ? $cached['der'] : null;
        }
        if ($der === null) {
            try {
                $body = ($this->aiaTransport ?? new CurlTransport(true, 100_000))->get($url, $this->options->aiaTimeoutSeconds);
                if (strlen($body) > 100_000) {
                    $body = '';
                }
                $pem = $this->parser->normalizePem($body) ?? $this->parser->normalizePem("-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($body), 64, "\n") . "-----END CERTIFICATE-----\n");
                $der = $pem !== null && @openssl_x509_parse($pem) !== false ? base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $pem), true) : false;
                $der = is_string($der) ? $der : '';
                if (is_string($pem) && $der !== '') {
                    $anchored = false;
                    foreach ($anchors as $anchor) {
                        if (self::signedBy($pem, $anchor, $at, $depth + 1)) {
                            $anchored = true;
                            break;
                        }
                    }
                    if (! $anchored) {
                        $der = '';
                    }
                }
            } catch (Throwable) {
                $der = '';
            }
            $ttl = $der === '' ? 300 : 3600;
            $this->aiaCache[$key] = ['der' => $der, 'expires' => time() + $ttl];
            try {
                $this->aiaCacheStore?->set($key, $der, $ttl);
            } catch (Throwable) {
                // A cache outage must not change the certificate decision.
            }
        }
        if ($der === '') {
            return null;
        }
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
        if (! self::signedBy($child->pem, $pem, $at, $depth)) {
            return null;
        }
        foreach ($anchors as $anchor) {
            if (self::signedBy($pem, $anchor, $at, $depth + 1)) {
                return $pem;
            }
        }

        return null;
    }

    private static function keyIdentifier(mixed $value): ?string
    {
        if (! is_string($value) || ! preg_match('/(?:keyid:)?\s*([0-9a-f]{2}(?::[0-9a-f]{2}){7,})/i', $value, $match)) {
            return null;
        }

        return strtolower($match[1]);
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
