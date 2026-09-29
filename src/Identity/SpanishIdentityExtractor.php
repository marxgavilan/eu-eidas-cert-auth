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
            $identifier = $match[0];
        }
        if ($organizationIdentifier === null && preg_match('/\(R:\s*([A-Z][0-9]{7}[0-9A-J])\)/', $cn, $match)) {
            $organizationIdentifier = $match[1];
        }
        $kind = $identifier === null && $organizationIdentifier !== null ? 'legal' : ($identifier !== null && $organizationIdentifier !== null ? 'representative' : 'natural');

        return new Identity($base->givenName, $base->surnames, $identifier, 'ES', $kind, $base->organization, $organizationIdentifier, $kind === 'representative' ? 'legal_entity' : null, $base->identifierScheme ?? ($identifier === null ? null : 'IDC'));
    }
}
