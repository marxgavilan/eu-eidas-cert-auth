<?php

declare(strict_types=1);

use Iberfacil\EidasCertAuth\Options;

return [
    'region' => env('EIDAS_REGION', 'ES'),
    'countries' => array_values(array_filter(array_map(static fn(string $country): string => strtoupper(trim($country)), explode(',', (string) env('EIDAS_COUNTRIES', ''))))),
    'service_types' => ['http://uri.etsi.org/TrstSvc/Svctype/CA/QC'],
    'lotl_signer_fingerprints' => Options::OJ_FINGERPRINTS,
    'store_path' => env('EIDAS_STORE_PATH', storage_path('app/eidas-trust')),
    'minimum_retention_percent' => (int) env('EIDAS_MINIMUM_RETENTION', 80),
    'timeout_seconds' => (int) env('EIDAS_TIMEOUT', 15),
    'require_qualified' => (bool) env('EIDAS_REQUIRE_QUALIFIED', false),
    'authentication_policies' => Options::DEFAULT_AUTHENTICATION_POLICIES,
    // Each named profile may override countries, qualified_required, person_types,
    // dnie, authentication_policies (country => OIDs), and soft_fail_revocation.
    // EIDAS_PROFILES may contain a JSON object with the same structure.
    'profiles' => json_decode((string) env('EIDAS_PROFILES', '{}'), true, flags: JSON_THROW_ON_ERROR),
    'require_fore_signatures' => true,
    'maximum_store_age_seconds' => 2592000,
    'intermediates' => [],
    'soft_fail_revocation' => (bool) env('EIDAS_SOFT_FAIL_REVOCATION', false),
    'revocation_cache_store' => env('EIDAS_REVOCATION_CACHE_STORE'),
    'server_variable' => 'SSL_CLIENT_CERT',
    'trusted_proxy_ips' => [],
    'trusted_proxy_header' => null,
    'schedule_daily' => true,
];
