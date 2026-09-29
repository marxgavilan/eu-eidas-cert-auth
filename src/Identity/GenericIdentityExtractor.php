<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Identity;

use Iberfacil\EidasCertAuth\Contracts\IdentityExtractor;
use Iberfacil\EidasCertAuth\Data\Identity;
use Iberfacil\EidasCertAuth\Data\ParsedCertificate;

class GenericIdentityExtractor implements IdentityExtractor
{
    public function supports(string $country): bool
    {
        return true;
    }

    public function extract(ParsedCertificate $certificate): Identity
    {
        $subject = $certificate->subject;
        $subjectCountry = strtoupper(self::field($subject, ['C', 'countryName']) ?? '');
        $personal = self::identifier(self::field($subject, ['serialNumber']));
        $organization = self::identifier(self::field($subject, ['organizationIdentifier', '2.5.4.97']));
        $country = $personal['country'] ?? $organization['country'] ?? $subjectCountry;
        $given = self::field($subject, ['GN', 'givenName']);
        $surname = self::field($subject, ['SN', 'surname']);
        $org = self::field($subject, ['O', 'organizationName']);
        $kind = $personal === null && $organization !== null ? 'legal' : ($personal !== null && $organization !== null ? 'representative' : 'natural');

        return new Identity($given, $surname, $personal['value'] ?? null, $country, $kind, $org, $organization['value'] ?? null, $kind === 'representative' ? 'legal_entity' : null, $personal['scheme'] ?? null);
    }

    /**
     * @param array<string, mixed> $subject
     * @param list<string> $keys
     */
    protected static function field(array $subject, array $keys): ?string
    {
        foreach ($keys as $key) {
            $value = $subject[$key] ?? null;
            $value = is_array($value) ? reset($value) : $value;
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }

        return null;
    }

    /** @return array{scheme: string, country: string, value: string}|null */
    protected static function identifier(?string $raw): ?array
    {
        if ($raw === null || ! preg_match('/^(IDC|PAS|TIN|VAT|NTR|PSD|LEI)([A-Z]{2})-(.+)$/i', trim($raw), $match)) {
            return null;
        }

        return ['scheme' => strtoupper($match[1]), 'country' => strtoupper($match[2]), 'value' => trim($match[3])];
    }
}
