<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth;

use InvalidArgumentException;

final readonly class Options
{
    public const LOTL_URL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

    /** SHA-256 fingerprints in OJ C/2026/1944, 15 April 2026. */
    public const OJ_FINGERPRINTS = [
        'c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5',
        'e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1',
        'df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5',
        'b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18',
        '236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b',
        'd2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474',
    ];

    /**
     * @param list<string> $countries
     * @param list<string> $serviceTypes
     * @param list<string> $lotlSignerFingerprints
     */
    public function __construct(
        public string $region = 'ES',
        public array $countries = [],
        public array $serviceTypes = ['http://uri.etsi.org/TrstSvc/Svctype/CA/QC'],
        public array $lotlSignerFingerprints = self::OJ_FINGERPRINTS,
        public int $minimumRetentionPercent = 80,
        public int $timeoutSeconds = 15,
        public bool $requireQualified = true,
        public bool $softFailRevocation = false,
    ) {
        if (! preg_match('/^[A-Z]{2}$/', $region) || $minimumRetentionPercent < 0 || $minimumRetentionPercent > 100 || $timeoutSeconds < 1) {
            throw new InvalidArgumentException('Invalid eIDAS options.');
        }
    }

    /** @return list<string> */
    public function acceptedCountries(): array
    {
        return $this->countries === [] ? [$this->region] : $this->countries;
    }
}
