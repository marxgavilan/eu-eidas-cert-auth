<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Identity;

use Iberfacil\EidasCertAuth\Data\Identity;
use Iberfacil\EidasCertAuth\Data\ParsedCertificate;

final class SpanishIdentityExtractor extends GenericIdentityExtractor
{
    public function supports(string $country): bool
    {
        return $country === 'ES';
    }

    public function extract(ParsedCertificate $certificate): Identity
    {
        $base = parent::extract($certificate);
        $cn = strtoupper(self::field($certificate->subject, ['CN', 'commonName']) ?? '');
        $identifier = $base->identifier;
        $organizationIdentifier = $base->organizationIdentifier;
        if ($identifier === null && preg_match('/\b(?:[0-9]{8}|[XYZ][0-9]{7})[A-Z]\b/', $cn, $match)) {
            if (self::validDni($match[0])) {
                $identifier = $match[0];
            }
        }
        if ($organizationIdentifier === null && preg_match('/\(R:\s*([A-Z][0-9]{7}[0-9A-J])\)/', $cn, $match)) {
            $organizationIdentifier = $match[1];
        }
        $kind = $identifier === null && $organizationIdentifier !== null ? 'legal' : ($identifier !== null && $organizationIdentifier !== null ? 'representative' : 'natural');

        return new Identity($base->givenName, $base->surnames, $identifier, 'ES', $kind, $base->organization, $organizationIdentifier, $kind === 'representative' ? 'legal_entity' : null, $base->identifierScheme ?? ($identifier === null ? null : 'IDC'));
    }

    private static function validDni(string $value): bool
    {
        $number = substr($value, 0, -1);
        if (preg_match('/^[XYZ]/', $number)) {
            $number = strtr($number, ['X' => '0', 'Y' => '1', 'Z' => '2']);
        }

        return ctype_digit($number) && 'TRWAGMYFPDXBNJZSQVHLCKE'[(int) $number % 23] === substr($value, -1);
    }
}
