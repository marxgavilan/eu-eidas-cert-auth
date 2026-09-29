<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth;

use InvalidArgumentException;

final readonly class ValidationProfile
{
    /**
     * @param list<string> $countries
     * @param list<'natural'|'representative'|'legal'> $personTypes
     * @param array<string, list<string>> $authenticationPolicies
     */
    public function __construct(
        public array $countries,
        public bool $qualifiedRequired = false,
        public array $personTypes = ['natural', 'representative'],
        public bool $dnie = true,
        public array $authenticationPolicies = [],
        public bool $softFailRevocation = false,
    ) {
        if ($countries === [] || ! array_is_list($countries) || count(array_unique($countries)) !== count($countries)) {
            throw new InvalidArgumentException('Invalid profile countries.');
        }
        foreach ($countries as $country) {
            if (! is_string($country) || ! preg_match('/^[A-Z]{2}$/D', $country)) {
                throw new InvalidArgumentException('Invalid profile country.');
            }
        }
        if ($personTypes === [] || ! array_is_list($personTypes) || count(array_unique($personTypes)) !== count($personTypes)) {
            throw new InvalidArgumentException('Invalid profile person types.');
        }
        foreach ($personTypes as $type) {
            if (! in_array($type, ['natural', 'representative', 'legal'], true)) {
                throw new InvalidArgumentException('Invalid profile person type.');
            }
        }
        foreach ($authenticationPolicies as $country => $policies) {
            if (! is_string($country) || ! preg_match('/^[A-Z]{2}$/D', $country) || ! is_array($policies) || ! array_is_list($policies) || $policies === []) {
                throw new InvalidArgumentException('Invalid profile authentication policies.');
            }
            foreach ($policies as $oid) {
                if (! is_string($oid) || ! preg_match('/^\d+(?:\.\d+)+$/D', $oid)) {
                    throw new InvalidArgumentException('Invalid profile authentication policy OID.');
                }
            }
        }
    }
}
