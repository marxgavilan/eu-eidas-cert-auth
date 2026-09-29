<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Certificate;

use DateTimeImmutable;
use Iberfacil\EidasCertAuth\Contracts\IdentityExtractor;
use Iberfacil\EidasCertAuth\Data\ParsedCertificate;
use Iberfacil\EidasCertAuth\Data\ValidationResult;
use Iberfacil\EidasCertAuth\Identity\FrenchIdentityExtractor;
use Iberfacil\EidasCertAuth\Identity\GenericIdentityExtractor;
use Iberfacil\EidasCertAuth\Identity\GermanIdentityExtractor;
use Iberfacil\EidasCertAuth\Identity\ItalianIdentityExtractor;
use Iberfacil\EidasCertAuth\Identity\PortugueseIdentityExtractor;
use Iberfacil\EidasCertAuth\Identity\SpanishIdentityExtractor;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Trust\TrustStore;

final readonly class CertificateValidator
{
    /**
     * @param list<IdentityExtractor> $extractors
     * @param list<string> $intermediates
     */
    public function __construct(private CertificateParser $parser, private TrustStore $store, private RevocationChecker $revocation, private Options $options, private array $extractors = [], private array $intermediates = []) {}

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
        $issuer = $this->issuer($parsed, $at);
        if ($issuer === null) {
            return ValidationResult::reject('untrusted', $parsed);
        }
        if ($parsed->keyUsage === null || ! str_contains($parsed->keyUsage, 'Digital Signature') || $parsed->extendedKeyUsage === null || (! str_contains($parsed->extendedKeyUsage, 'TLS Web Client Authentication') && ! str_contains($parsed->extendedKeyUsage, 'clientAuth'))) {
            return ValidationResult::reject('not_for_authentication', $parsed);
        }
        if ($this->options->requireQualified && ! $parsed->qualified) {
            return ValidationResult::reject('not_qualified', $parsed);
        }
        $subjectCountry = strtoupper((string) ($parsed->subject['C'] ?? ''));
        $generic = (new GenericIdentityExtractor())->extract($parsed);
        $country = $generic->country !== '' ? $generic->country : $subjectCountry;
        if (! in_array($country, $this->options->acceptedCountries(), true)) {
            return ValidationResult::reject('country_not_accepted', $parsed);
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
        $revocation = $this->revocation->check($parsed, $issuer);
        if ($revocation['status'] === 'revoked') {
            return ValidationResult::reject('revoked', $parsed);
        }
        if ($revocation['status'] !== 'good' && ! $this->options->softFailRevocation) {
            return ValidationResult::reject('revocation_unavailable', $parsed);
        }

        return new ValidationResult(true, null, $identity, $parsed, $revocation['source']);
    }

    private function issuer(ParsedCertificate $certificate, DateTimeImmutable $at): ?string
    {
        $anchors = $this->store->certificates();
        $pool = $this->intermediates;
        $current = $certificate->pem;
        $direct = null;
        for ($depth = 0; $depth < 5; $depth++) {
            foreach ($anchors as $anchor) {
                if (self::signedBy($current, $anchor, $at)) {
                    return $direct ?? $anchor;
                }
            }
            $next = null;
            foreach ($pool as $pem) {
                if (self::signedBy($current, $pem, $at)) {
                    $next = $pem;
                    break;
                }
            }
            if ($next === null || $next === $current) {
                return null;
            }
            $direct ??= $next;
            $current = $next;
        }

        return null;
    }

    private static function signedBy(string $child, string $issuer, DateTimeImmutable $at): bool
    {
        $c = @openssl_x509_parse($child);
        $i = @openssl_x509_parse($issuer);
        if (! is_array($c) || ! is_array($i) || ($c['issuer'] ?? null) != ($i['subject'] ?? null) || ! str_contains((string) ($i['extensions']['basicConstraints'] ?? ''), 'CA:TRUE') || (int) ($i['validFrom_time_t'] ?? 0) > $at->getTimestamp() || (int) ($i['validTo_time_t'] ?? 0) < $at->getTimestamp()) {
            return false;
        }
        $key = @openssl_pkey_get_public($issuer);

        return $key !== false && @openssl_x509_verify($child, $key) === 1;
    }
}
