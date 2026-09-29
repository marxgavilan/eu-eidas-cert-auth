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

    public const DEFAULT_AUTHENTICATION_POLICIES = [];

    /**
     * @param list<string> $countries
     * @param list<string> $serviceTypes
     * @param list<string> $lotlSignerFingerprints
     * @param array<string, list<string>> $authenticationPolicies
     * @param array<string, array<string, mixed>> $profiles
     * @param list<string> $aiaAllowedHosts
     */
    public function __construct(
        public string $region = 'ES',
        public array $countries = [],
        public array $serviceTypes = ['http://uri.etsi.org/TrstSvc/Svctype/CA/QC'],
        public array $lotlSignerFingerprints = self::OJ_FINGERPRINTS,
        public int $minimumRetentionPercent = 80,
        public int $timeoutSeconds = 15,
        public bool $requireQualified = false,
        public bool $softFailRevocation = false,
        public bool $requireForeSignatures = true,
        public int $maximumStoreAgeSeconds = 2592000,
        public array $authenticationPolicies = self::DEFAULT_AUTHENTICATION_POLICIES,
        public array $profiles = [],
        public bool $aiaFetch = true,
        public array $aiaAllowedHosts = [],
        public int $aiaTimeoutSeconds = 4,
    ) {
        if (! preg_match('/^[A-Z]{2}$/', $region) || $minimumRetentionPercent < 0 || $minimumRetentionPercent > 100 || $timeoutSeconds < 1 || $maximumStoreAgeSeconds < 1 || $aiaTimeoutSeconds < 3 || $aiaTimeoutSeconds > 5) {
            throw new InvalidArgumentException('Invalid eIDAS options.');
        }
        if (! array_is_list($aiaAllowedHosts)) {
            throw new InvalidArgumentException('Invalid AIA allowed hosts.');
        }
        foreach ($aiaAllowedHosts as $host) {
            if (! is_string($host) || $host === '' || strtolower($host) !== $host || ! preg_match('/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/D', $host)) {
                throw new InvalidArgumentException('Invalid AIA allowed host.');
            }
        }
        $seen = [];
        foreach ($countries as $country) {
            if (! is_string($country) || ! preg_match('/^[A-Z]{2}$/', $country) || isset($seen[$country])) {
                throw new InvalidArgumentException('Invalid accepted country.');
            }
            $seen[$country] = true;
        }
        foreach ($authenticationPolicies as $country => $policies) {
            if (! is_string($country) || ! preg_match('/^[A-Z]{2}$/', $country) || ! is_array($policies) || ! array_is_list($policies)) {
                throw new InvalidArgumentException('Invalid authentication policies.');
            }
            foreach ($policies as $oid) {
                if (! is_string($oid) || ! preg_match('/^\d+(?:\.\d+)+$/D', $oid)) {
                    throw new InvalidArgumentException('Invalid authentication policy OID.');
                }
            }
        }
        foreach (array_keys($profiles) as $name) {
            if (! is_string($name) || ! preg_match('/^[A-Za-z][A-Za-z0-9_-]*$/D', $name)) {
                throw new InvalidArgumentException('Invalid eIDAS validation profile name.');
            }
            $this->profile($name);
        }
    }

    /** @return list<string> */
    public function acceptedCountries(): array
    {
        return $this->countries === [] ? [$this->region] : $this->countries;
    }

    public function profile(string $name = 'default'): ValidationProfile
    {
        if ($name === '' || ($name !== 'default' && ! array_key_exists($name, $this->profiles))) {
            throw new InvalidArgumentException("Unknown eIDAS validation profile: {$name}");
        }
        $settings = $this->profiles[$name] ?? [];
        if (! is_array($settings)) {
            throw new InvalidArgumentException("Invalid eIDAS validation profile: {$name}");
        }
        $allowed = ['countries', 'qualified_required', 'person_types', 'dnie', 'authentication_policies', 'soft_fail_revocation', 'aia_fetch'];
        foreach ($settings as $key => $value) {
            if (! in_array($key, $allowed, true)) {
                throw new InvalidArgumentException("Unknown eIDAS profile setting: {$key}");
            }
            if (in_array($key, ['qualified_required', 'dnie', 'soft_fail_revocation', 'aia_fetch'], true) && ! is_bool($value)) {
                throw new InvalidArgumentException("Invalid eIDAS profile setting: {$key}");
            }
        }
        foreach (['countries', 'person_types', 'authentication_policies'] as $key) {
            if (array_key_exists($key, $settings) && ! is_array($settings[$key])) {
                throw new InvalidArgumentException("Invalid eIDAS profile setting: {$key}");
            }
        }

        return new ValidationProfile(
            countries: $settings['countries'] ?? $this->acceptedCountries(),
            qualifiedRequired: $settings['qualified_required'] ?? $this->requireQualified,
            personTypes: $settings['person_types'] ?? ['natural', 'representative'],
            dnie: $settings['dnie'] ?? in_array('ES', $settings['countries'] ?? $this->acceptedCountries(), true),
            authenticationPolicies: array_filter($settings['authentication_policies'] ?? $this->authenticationPolicies),
            softFailRevocation: $settings['soft_fail_revocation'] ?? $this->softFailRevocation,
            aiaFetch: $settings['aia_fetch'] ?? $this->aiaFetch,
        );
    }
}
