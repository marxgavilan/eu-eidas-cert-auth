# eu-eidas-cert-auth

[![CI](https://github.com/marxgavilan/eu-eidas-cert-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/marxgavilan/eu-eidas-cert-auth/actions/workflows/ci.yml) [![Packagist](https://img.shields.io/packagist/v/iberfacil/eidas-cert-auth.svg)](https://packagist.org/packages/iberfacil/eidas-cert-auth) [![PHP](https://img.shields.io/packagist/php-v/iberfacil/eidas-cert-auth.svg)](https://packagist.org/packages/iberfacil/eidas-cert-auth) [![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Let people sign in to your website or application with a digital certificate—FNMT, DNIe, or one from any qualified EU provider—while checking that it is valid, issued under an official trusted authority, and not revoked. Framework-free, with a CLI and an optional Laravel adapter.

[Versión en español](README.md)

Created by Marco Gavilán, of IBERFÁCIL.

---

## What it is for (non-technical)

Passwords are forgotten, reused and stolen. When an accounting firm, law office or public administration opens a private area, it needs to know who is signing in: a client, a company representative, or someone impersonating them. A name and tax ID typed into a form do not prove identity.

This package lets your application use the visitor's digital certificate:

1. Check the **signed official EU trusted list** to identify accepted authorities and providers.
2. Check certificate dates, the chain to an accepted authority, and whether it is suitable for the requested operation.
3. Check **revocation**; if revocation cannot be checked, access is rejected by default.
4. Extract the certificate's identity claims, such as name, Spanish NIF or equivalent identifier, and company representation when present. Your application decides which account that identity belongs to.

| What you see | What it means |
| --- | --- |
| **Valid** (`valid: true`) | The certificate passes the selected profile; your application can then match the identity to an account. |
| **Expired or not yet valid** (`expired`, `not_yet_valid`) | The certificate is outside its validity dates. |
| **Revoked** (`revoked`) | Its issuer has cancelled it; deny access. |
| **Revocation unavailable** (`revocation_unavailable`) | Neither OCSP nor CRL provided a trustworthy answer; reject by default and retry when the service returns. |
| **Untrusted or unsuitable** (`untrusted`, `no_authentication_usage`, `no_signature_usage`) | The chain does not reach an accepted authority, or the certificate lacks the required use. |
| **Profile rules not met** (`country_not_accepted`, `qualified_required`, `dnie_disabled_for_profile`, `authentication_policy_mismatch`, `person_type_not_allowed`) | This operation requires a country, person type, policy or qualification the certificate does not meet. |
| **Identity unavailable** (`no_personal_identity`, `malformed`) | There is no usable identifier, or the certificate cannot be parsed. |

Examples: a firm lets clients into a private area; a law office distinguishes individuals from company representatives; an administration applies a stricter profile to sensitive operations; an onboarding service binds a verified certificate identity to an account; an application reserves its signing flow for certificates that satisfy a qualified profile.

**What you need:** a web server configured to request client certificates, an up-to-date private trust store, and validation on every protected route. Your application still decides permissions and whether a claimed representation suffices for a particular transaction. This package does not itself perform electronic signing.

---

## For developers

### Requirements and installation

PHP 8.2+ with `curl`, `dom`, `libxml`, and `openssl`; the `openssl` executable is needed for RSA-PSS, OCSP and CRL verification. Install with `composer require iberfacil/eidas-cert-auth`. For this checkout, run `composer install`.

The runtime PHP dependencies are `robrichards/xmlseclibs` and `psr/simple-cache`. The former handles XMLDSig canonicalization and RSA signatures. We require 3.1.5 or newer in that branch and independently constrain transforms, same-document references, SHA-2 algorithms, signer fingerprints, and the signed root. RSA-PSS signatures, used by the current German TSL, are verified with the OpenSSL executable after the same signed-reference checks. The current EU LOTL also has an XAdES signed-properties reference; every reference digest is checked before signature verification. See the [library releases](https://github.com/robrichards/xmlseclibs/releases) and the [EU pivot explanation](https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html).

### Trust-list import and CLI

The default source is the [European LOTL](https://ec.europa.eu/tools/lotl/eu-lotl.xml). The default accepted country is the configured region (`ES`); other countries must be explicitly listed. Only configured `CA/QC` service types with a `granted` status and the `ForeSignatures` indication contribute CA certificates by default. ETSI `NotQualified` and `QCForLegalPerson` qualifiers describe certificates matching their criteria; they do not remove an entire CA service from the store. A profile requiring qualification applies their key-usage and certificate-policy criteria to the client certificate; unsupported criteria fail closed for qualification. Service history is used when evaluating an earlier date. Each certificate becomes `<sha256>.pem`; `bundle.pem` concatenates the current set. `manifest.json` records country, service type, publication time, list expiry and per-country sequence numbers.

The LOTL signer must match a pinned SHA-256 fingerprint from [Official Journal C/2026/1944, 15 April 2026](https://eur-lex.europa.eu/eli/C/2026/1944/oj/eng). The six published fingerprints are defaults in `Options::OJ_FINGERPRINTS` and `config/eidas-cert-auth.php`. Review that notice and the [pivot mechanism](https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html) before changing pins; the package does not automatically follow pivot LOTLs. Each national TSL signer must match a certificate in the signed LOTL pointer for that country. A standalone TSL requires caller-supplied signer pins.

```bash
mkdir -p /path/to/private-data
vendor/bin/eidas-cert-auth trust-list:update --store=/path/to/private-data/trust --region=ES --dry-run
vendor/bin/eidas-cert-auth trust-list:update --store=/path/to/private-data/trust --region=ES
vendor/bin/eidas-cert-auth doctor --store=/path/to/private-data/trust
```

The live path is an atomic symlink to a generation directory beside it. Its parent must exist and be writable; the live path must be absent or already be a symlink. Use `--dry-run` to verify signatures and print additions/removals without changing it; a count-guard failure is reported after the diff. An update with fewer than 80% of the previous CA count in any country is rejected unless `--force` is given. `--force` affects only the count guard; invalid signatures and empty imports always fail. Old generations remain available for rollback and should be pruned under your retention policy. The generation directory is mode 0700: run updates as the same user as the validator, or grant that user access through deployment permissions. The validator rejects a store after its earliest list NextUpdate or 30 days without a successful update by default; configure the maximum age to match your update schedule. A published store also preserves the highest observed sequence number for each country and the LOTL across updates, including when a country is temporarily removed. Stores created by earlier versions need one successful update to gain expiry and sequence metadata before validation can use them.

Framework-free use:

```php
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Transport\CurlTransport;
use Iberfacil\EidasCertAuth\Trust\{TrustListImporter, TrustStore, XmlSignatureVerifier};

$options = new Options(region: 'PT', countries: ['PT', 'ES']);
$store = new TrustStore('/path/to/private-data/trust', $options->minimumRetentionPercent);
$importer = new TrustListImporter(new CurlTransport(), new XmlSignatureVerifier(), $store, $options);
$result = $importer->importLotl(dryRun: true);
// $importer->importLotl(force: false);
```

For a standalone TSL, obtain signer fingerprints from a separately verified LOTL or a trusted out-of-band publication, then call `importTsl($signedXml, 'ES', $pins)`. Never trust a signer certificate merely because it appears inside the TSL being checked.

## Client validation and identity

`CertificateValidator::validate()` returns a typed `ValidationResult` with `valid`, `reason`, `identity`, `certificate`, `revocationSource`, and the requested `profile`. It checks parsing, validity dates, every chain signature to a CA in the current store, CA constraints, the usage required by the profile, qualification requirements, accepted country, a personal identifier, and revocation. OCSP is tried first; CRL is a verified fallback. Responses are verified by OpenSSL against the issuer, have timeouts, and are cached by SHA-256 certificate fingerprint. Unavailable revocation fails closed by default; `softFailRevocation` is an explicit policy choice.

Identity extraction exposes given name, surnames, identifier, country, person type (`natural`, `representative`, `legal`), organization, organization identifier, representation, and identifier scheme. There are extractors for ES, PT, IT, FR, and DE, plus a generic ETSI EN 319 412-1 extractor for `IDC`, `PAS`, `TIN`, and `VAT` semantics. The Spanish extractor also handles `IDCES-`, `VATES-`, a bare DNI/NIE in `serialNumber` with a valid check letter, and a representative ID in a common name. These fields are claims in the certificate; applications must bind accounts by `(scheme, country, value)` and verify the intended person type, rather than matching `value` alone.

```php
use Iberfacil\EidasCertAuth\Cache\InMemoryRevocationCache;
use Iberfacil\EidasCertAuth\Certificate\{CertificateParser, CertificateValidator, RevocationChecker};
use Iberfacil\EidasCertAuth\Transport\CurlTransport;

$validator = new CertificateValidator(
    new CertificateParser(), $store,
    new RevocationChecker(new CurlTransport(allowHttp: true), new InMemoryRevocationCache()),
    $options,
);
$result = $validator->validate($pemFromServerVariable);
if (! $result->valid) {
    // Use $result->reason; do not log the PEM or identity by default.
}
```

Revocation and AIA issuer URLs in client certificates can use HTTP. Transport forbids redirects, rejects private or reserved DNS answers, pins the resolved public address, and bounds download time and size; deploy egress filtering as well. For a process-wide revocation cache, inject your own `RevocationCache`. OCSP good responses require a recent thisUpdate and nextUpdate.

### Authentication rule and profiles

The default `default` profile accepts a client certificate whose verified chain reaches an accepted CA/QC TSL anchor with `ForeSignatures`, and declares authentication use: a present EKU contains `clientAuth`, or an absent EKU is paired with keyUsage `digitalSignature`. It does not require QcCompliance or a particular certificate-policy OID. This rule supports login with certificates such as DNIe authentication certificates; the leaf must still pass date, chain, country, identity and revocation checks. A profile can impose stricter requirements for a particular route.

`usage` defaults to `authentication` for every profile, including existing ones. Set `'usage' => 'signature'` for signing certificates: keyUsage must include `nonRepudiation`/`contentCommitment` or `digitalSignature`. When EKU is present, it must include `emailProtection`, `documentSigning` (`1.3.6.1.5.5.7.3.36`), `anyExtendedKeyUsage`, or `clientAuth`. A `clientAuth` EKU alone cannot replace signing keyUsage. Rejection for missing signing use returns `no_signature_usage`. Chain, trust, qualification, country, person type, and revocation checks keep their existing rules.

**Risk:** The default profile accepts non-qualified certificates, and the strength of identity verification depends on each provider's issuance practice. If the TSL lists a root such as AC RAIZ DNIE 2, every subordinate CA under that root is within the chain scope, including CAs issuing non-qualified certificates. AIA retrieval makes an outbound request to a URL supplied by the client certificate before its chain is trusted; restrict egress with `aia_allowed_hosts` and a firewall. For high-risk actions such as signing, registration or granting powers, use a profile with `qualified_required` or explicit authentication-policy OIDs.

The [Spanish Police DNIe certification practice statement, version 3.2, sections 7.1.4 and 7.1.6](https://www.dnielectronico.es/PDFs/Politicas_de_certificacion_v3.2.pdf) documents the authentication OID `2.16.724.1.2.2.2.4`, `digitalSignature`, no EKU, and a bare DNI/NIE `serialNumber`. The OID is **optional**: set `authentication_policies` only when the application needs to restrict a profile to those OIDs. For that DNIe OID, the documented two-number version suffix is accepted. The `dnie` switch identifies DNIe by the verified TSL anchor certificate subject containing `DNIE`, not by untrusted text in the leaf.

Publish the Laravel config with `php artisan vendor:publish --tag=eidas-cert-auth-config` and set `profiles` there (or set `EIDAS_PROFILES` to the equivalent JSON object in `.env`). Example: DNIe only for login, qualified certificates for signing, and no DNIe for onboarding:

```php
'profiles' => [
    'default' => [
        'countries' => ['ES'], 'qualified_required' => false,
        'person_types' => ['natural', 'representative'], 'dnie' => true,
        'soft_fail_revocation' => false,
    ],
    'login' => [
        'countries' => ['ES'], 'qualified_required' => false,
        'person_types' => ['natural', 'representative'], 'dnie' => true,
        'soft_fail_revocation' => false,
    ],
    'signature' => [
        'usage' => 'signature', 'countries' => ['ES'], 'qualified_required' => true,
        'person_types' => ['natural', 'representative'], 'dnie' => false,
        'soft_fail_revocation' => false,
    ],
    'onboarding' => [
        'countries' => ['ES', 'PT'], 'qualified_required' => false,
        'person_types' => ['natural', 'representative', 'legal'], 'dnie' => false,
        'soft_fail_revocation' => false,
    ],
],
```

A qualified profile requires QcCompliance and applies the TSL's `NotQualified`/`QCForLegalPerson` criteria. `person_types` can include `natural`, `representative`, and `legal` (an entity seal with an organization identifier). A `legal` certificate still needs the configured usage. Set `authentication_policies` on a profile as a country-to-OID map, for example `'authentication_policies' => ['ES' => ['2.16.724.1.2.2.2.4']]`; omission means no OID restriction. `soft_fail_revocation` defaults to `false` per profile. Omitted fields inherit the global defaults; `default` is available without configuration, accepts ES and DNIe, and does not require qualification. Unknown names raise `InvalidArgumentException`. Distinct rejection reasons include `no_authentication_usage`, `no_signature_usage`, `dnie_disabled_for_profile`, `qualified_required`, `authentication_policy_mismatch`, and `person_type_not_allowed`.

```php
// Laravel route using the eidas.cert alias registered by the provider:
Route::post('/sign', $handler)->middleware('eidas.cert:signature');

// Framework-free validator or Laravel facade:
$result = $validator->validate($pemFromServerVariable, profile: 'signature');
```

The leaf often arrives without `AC DNIE 00x`. If its issuer DN or authority key is not already in the store, the validator may fetch only the leaf's first AIA `caIssuers` URL. It accepts the downloaded CA only when that CA signs the leaf and is directly signed by a current TSL anchor; no further AIA hop is attempted. The request has a configurable 3–5 second timeout (`aia_timeout_seconds`, default 4) and a 100 KB response limit. `aia_fetch` defaults to `true` and can be disabled globally or per profile; `aia_allowed_hosts` is an optional exact-host allowlist. Successful CA downloads are cached for one hour and failed downloads for five minutes. Laravel uses `aia_cache_store` (or its default cache store); choose a shared cache driver for multi-worker deployments. Framework-free callers can inject a PSR-16 cache as `aiaCacheStore`. Cached entries contain only downloaded CA certificate DER, never the client leaf. The download is never a trust anchor. For offline or controlled deployments, pass PEM strings via `new CertificateValidator(..., intermediates: [$issuerPem])` or Laravel's `intermediates` array. Refresh older stores from signed lists to record `ForeSignatures` before using non-qualified authentication certificates.

## TLS termination: `optional_no_ca`

Use `ssl_verify_client optional_no_ca` on nginx or `SSLVerifyClient optional_no_ca` on Apache so clients can present certificates from multiple eIDAS issuers, while this library checks the signed trust lists, chain, purpose, identity and revocation in PHP. **`optional_no_ca` is not authentication by itself.** Protect every route with the middleware (or equivalent validation), keep the PHP origin unreachable from clients, and make the server variable impossible for a browser to set through an HTTP header. The [nginx directive](https://nginx.org/en/docs/http/ngx_http_ssl_module.html) and [Apache directive](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html) explicitly distinguish this mode from successful CA verification.

nginx with PHP-FPM, inside the certificate-only location:

```nginx
ssl_verify_client optional_no_ca;
ssl_client_certificate /path/to/private-data/trust/bundle.pem;

location /certificate-login {
    include fastcgi_params;
    fastcgi_param SSL_CLIENT_CERT $ssl_client_escaped_cert;
    fastcgi_param SCRIPT_FILENAME /path/to/public/index.php;
    fastcgi_pass php_backend;
}
```

`$ssl_client_escaped_cert` is URL-encoded; `CertificateParser` normalizes it. Ensure your FastCGI configuration cannot derive `SSL_CLIENT_CERT` from a request header and that all relevant routes execute validation. The example assumes a separately configured TLS server certificate, PHP upstream, and access controls.

Apache 2.4 with mod_ssl and mod_php:

```apache
SSLVerifyClient optional_no_ca
SSLCACertificateFile /path/to/private-data/trust/bundle.pem
SSLOptions +StdEnvVars +ExportCertData
<Location "/certificate-login">
    Require all granted
</Location>
```

`mod_ssl` exports `SSL_CLIENT_CERT` to the server environment when `+ExportCertData` is enabled. With PHP-FPM, configure and test the explicit environment transfer in your Apache/FastCGI setup. Never map a client-supplied `HTTP_SSL_CLIENT_CERT` or `X-SSL-Client-Cert` into this server variable.

## Laravel

The provider auto-registers when Laravel is installed. Publish configuration with `php artisan vendor:publish --tag=eidas-cert-auth-config`. Set `EIDAS_STORE_PATH`, `EIDAS_REGION`, and optionally `EIDAS_COUNTRIES` (comma separated). In the published config, set `service_types`, `minimum_retention_percent`, signer pins, `profiles`, optional global `authentication_policies`, `soft_fail_revocation`, and an optional `revocation_cache_store`, `intermediates` and `maximum_store_age_seconds` to your policy. Laravel uses its cache for revocation results. `schedule_daily=true` registers `eidas:trust-list:update` daily by default; set it to `false` if your application schedules updates itself. The application still needs its normal scheduler trigger.

```bash
php artisan eidas:trust-list:update --dry-run
php artisan eidas:trust-list:update
php artisan eidas:doctor
```

Apply `Iberfacil\EidasCertAuth\Laravel\Middleware\ValidateClientCertificate` to the protected route. It reads the configured server variable (`SSL_CLIENT_CERT` by default), validates it, and places `eidas.identity` and `eidas.validation` in request attributes. Headers are ignored by default. To use a trusted reverse proxy, set **both** `trusted_proxy_header` and exact `trusted_proxy_ips`; the middleware compares `REMOTE_ADDR`, not forwarded client IP. Ensure that proxy strips incoming copies of the header and sets its own verified value. Events: `TrustListUpdated` after a successful published update; `TrustListRejected` on an update failure. The `EidasCertAuth` facade resolves the validator.

## Security and limits

- Review countries, service types, profiles, Official Journal signer pins and revocation policy with the application owner before opening routes to the public. The initial `region` is `ES`.
- Protect every authentication route with `ValidateClientCertificate` or equivalent validation. Restrict direct access to the PHP origin; accept certificate headers only from an exact-IP trusted proxy that strips client-supplied copies.
- Keep the trust store private and writable. Review additions and removals from `--dry-run` before publishing an update; use `--force` only after investigating a count drop.
- Do not store or log certificate PEMs, private keys, identity data or revocation responses without a privacy policy designed for them. Bind accounts by identifier scheme, country and value, and verify the representation required for each transaction.

## Development

```bash
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse --memory-limit=512M
vendor/bin/pint --test
```

Tests generate their CA hierarchy, client certificates, signed LOTL/TSLs and OCSP responses at runtime. `FakeTransport` keeps them offline. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [AGENTS.md](AGENTS.md).

## License

MIT. Copyright (c) 2026 Marco Gavilán — IBERFÁCIL. See [LICENSE](LICENSE).
