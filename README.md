# eidas-cert-auth

Framework-free PHP 8.2+ library for certificate-based client authentication against signed eIDAS trusted lists. It verifies the European LOTL, follows its signed national TSL pointers, publishes qualified CA certificates atomically, and validates a presented client certificate. Laravel support is optional and isolated in `src/Laravel/`.

[Español](README.es.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

## Requirements and installation

PHP 8.2+ with `curl`, `dom`, `libxml`, and `openssl`; the `openssl` executable is needed for RSA-PSS, OCSP and CRL verification. Install with `composer require iberfacil/eidas-cert-auth` when published. For this checkout, run `composer install`.

`robrichards/xmlseclibs` is the only runtime PHP library dependency. It handles XMLDSig canonicalization and RSA signatures. We require 3.1.5 or newer in that branch and independently constrain transforms, same-document references, SHA-2 algorithms, signer fingerprints, and the signed root. RSA-PSS signatures, used by the current German TSL, are verified with the OpenSSL executable after the same signed-reference checks. The current EU LOTL also has an XAdES signed-properties reference; every reference digest is checked before signature verification. See the [library releases](https://github.com/robrichards/xmlseclibs/releases) and the [EU pivot explanation](https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html).

## Trust-list import

The default source is the [European LOTL](https://ec.europa.eu/tools/lotl/eu-lotl.xml). The default accepted country is the configured region (`ES`); other countries must be explicitly listed. Only configured `CA/QC` service types with a `granted` status and the `ForeSignatures` indication contribute CA certificates by default. ETSI `NotQualified` and `QCForLegalPerson` qualifiers describe certificates matching their criteria; they do not remove an entire CA service from the store. Validation applies their key-usage and certificate-policy criteria to the client certificate; unsupported criteria fail closed for that CA. Service history is used when evaluating an earlier date. Each certificate becomes `<sha256>.pem`; `bundle.pem` concatenates the current set. `manifest.json` records country, service type, publication time, list expiry and per-country sequence numbers.

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

`CertificateValidator::validate()` returns a typed `ValidationResult` with `valid`, `reason`, `identity`, `certificate`, and `revocationSource`. It checks parsing, validity dates, every chain signature to a CA in the current store, CA constraints, digital-signature key usage, client-auth EKU, the ETSI QcCompliance statement by default, accepted country, a personal identifier, and revocation. OCSP is tried first; CRL is a verified fallback. Responses are verified by OpenSSL against the issuer, have timeouts, and are cached by SHA-256 certificate fingerprint. Unavailable revocation fails closed by default; `softFailRevocation` is an explicit policy choice.

Identity extraction exposes given name, surnames, identifier, country, person type (`natural`, `representative`, `legal`), organization, organization identifier, representation, and identifier scheme. There are extractors for ES, PT, IT, FR, and DE, plus a generic ETSI EN 319 412-1 extractor for `IDC`, `PAS`, `TIN`, and `VAT` semantics. The Spanish extractor also handles `IDCES-`, `VATES-`, and a representative ID in a common name. These fields are claims in the certificate; applications must bind accounts by `(scheme, country, value)` and verify the intended person type, rather than matching `value` alone.

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

Revocation URLs in client certificates can use HTTP. Transport forbids redirects, rejects private or reserved DNS answers, and pins the resolved public address for the request; deploy egress filtering as well. For a process-wide cache or intermediate certificates, inject your own `RevocationCache` or the validator's `intermediates` argument. OCSP good responses require a recent thisUpdate and nextUpdate.

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

The provider auto-registers when Laravel is installed. Publish configuration with `php artisan vendor:publish --tag=eidas-cert-auth-config`. Set `EIDAS_STORE_PATH`, `EIDAS_REGION`, and optionally `EIDAS_COUNTRIES` (comma separated). In the published config, set `service_types`, `minimum_retention_percent`, signer pins, `require_qualified`, `soft_fail_revocation`, and an optional `revocation_cache_store`, `intermediates` and `maximum_store_age_seconds` to your policy. Laravel uses its cache for revocation results. `schedule_daily=true` registers `eidas:trust-list:update` daily by default; set it to `false` if your application schedules updates itself. The application still needs its normal scheduler trigger.

```bash
php artisan eidas:trust-list:update --dry-run
php artisan eidas:trust-list:update
php artisan eidas:doctor
```

Apply `Iberfacil\EidasCertAuth\Laravel\Middleware\ValidateClientCertificate` to the protected route. It reads the configured server variable (`SSL_CLIENT_CERT` by default), validates it, and places `eidas.identity` and `eidas.validation` in request attributes. Headers are ignored by default. To use a trusted reverse proxy, set **both** `trusted_proxy_header` and exact `trusted_proxy_ips`; the middleware compares `REMOTE_ADDR`, not forwarded client IP. Ensure that proxy strips incoming copies of the header and sets its own verified value. Events: `TrustListUpdated` after a successful published update; `TrustListRejected` on an update failure. The `EidasCertAuth` facade resolves the validator.

## Development

```bash
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse --memory-limit=512M
vendor/bin/pint --test
```

Tests generate their CA hierarchy, client certificates, signed LOTL/TSLs and OCSP responses at runtime. `FakeTransport` keeps them offline. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [AGENTS.md](AGENTS.md).

MIT © 2026 Iberfacil contributors. See [LICENSE](LICENSE).
