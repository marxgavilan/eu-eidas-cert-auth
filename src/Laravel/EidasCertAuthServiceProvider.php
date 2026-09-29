<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Laravel;

use Iberfacil\EidasCertAuth\Certificate\CertificateParser;
use Iberfacil\EidasCertAuth\Certificate\CertificateValidator;
use Iberfacil\EidasCertAuth\Certificate\RevocationChecker;
use Iberfacil\EidasCertAuth\Contracts\RevocationCache;
use Iberfacil\EidasCertAuth\Contracts\Transport;
use Iberfacil\EidasCertAuth\Laravel\Console\DoctorCommand;
use Iberfacil\EidasCertAuth\Laravel\Console\TrustListUpdateCommand;
use Iberfacil\EidasCertAuth\Laravel\Middleware\ValidateClientCertificate;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Transport\CurlTransport;
use Iberfacil\EidasCertAuth\Trust\TrustListImporter;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use Iberfacil\EidasCertAuth\Trust\XmlSignatureVerifier;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use InvalidArgumentException;
use JsonException;

final class EidasCertAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/eidas-cert-auth.php', 'eidas-cert-auth');
        $this->app->singleton(Options::class, static function (Application $app): Options {
            $config = $app->make('config');
            $profiles = $config->get('eidas-cert-auth.profiles', []);
            if (is_string($profiles)) {
                try {
                    $profiles = json_decode($profiles, true, flags: JSON_THROW_ON_ERROR);
                } catch (JsonException $exception) {
                    throw new InvalidArgumentException('Invalid EIDAS_PROFILES JSON: ' . $exception->getMessage(), previous: $exception);
                }
            }
            if (! is_array($profiles) || ($profiles !== [] && array_is_list($profiles))) {
                throw new InvalidArgumentException('EIDAS_PROFILES must be a JSON object of named profiles.');
            }

            return new Options(
                region: (string) $config->get('eidas-cert-auth.region', 'ES'),
                countries: array_values(array_filter((array) $config->get('eidas-cert-auth.countries', []), 'is_string')),
                serviceTypes: array_values(array_filter((array) $config->get('eidas-cert-auth.service_types', []), 'is_string')),
                lotlSignerFingerprints: array_values(array_filter((array) $config->get('eidas-cert-auth.lotl_signer_fingerprints', Options::OJ_FINGERPRINTS), 'is_string')),
                minimumRetentionPercent: (int) $config->get('eidas-cert-auth.minimum_retention_percent', 80),
                timeoutSeconds: (int) $config->get('eidas-cert-auth.timeout_seconds', 15),
                requireQualified: (bool) $config->get('eidas-cert-auth.require_qualified', false),
                softFailRevocation: (bool) $config->get('eidas-cert-auth.soft_fail_revocation', false),
                requireForeSignatures: (bool) $config->get('eidas-cert-auth.require_fore_signatures', true),
                maximumStoreAgeSeconds: (int) $config->get('eidas-cert-auth.maximum_store_age_seconds', 2592000),
                authenticationPolicies: (array) $config->get('eidas-cert-auth.authentication_policies', Options::DEFAULT_AUTHENTICATION_POLICIES),
                profiles: $profiles,
                aiaFetch: (bool) $config->get('eidas-cert-auth.aia_fetch', true),
                aiaAllowedHosts: array_values((array) $config->get('eidas-cert-auth.aia_allowed_hosts', [])),
                aiaTimeoutSeconds: (int) $config->get('eidas-cert-auth.aia_timeout_seconds', 4),
            );
        });
        $this->app->singleton(TrustStore::class, static fn(Application $app): TrustStore => new TrustStore((string) $app->make('config')->get('eidas-cert-auth.store_path'), $app->make(Options::class)->minimumRetentionPercent, $app->make(Options::class)->maximumStoreAgeSeconds));
        $this->app->bindIf(Transport::class, static fn(): Transport => new CurlTransport());
        $this->app->bindIf(RevocationCache::class, static function (Application $app): RevocationCache {
            $configured = $app->make('config')->get('eidas-cert-auth.revocation_cache_store');
            $cache = $app->make(CacheFactory::class)->store(is_string($configured) && $configured !== '' ? $configured : null);

            return new LaravelRevocationCache($cache);
        });
        $this->app->singleton(TrustListImporter::class, static fn(Application $app): TrustListImporter => new TrustListImporter($app->make(Transport::class), new XmlSignatureVerifier(), $app->make(TrustStore::class), $app->make(Options::class)));
        $this->app->singleton(CertificateValidator::class, static function (Application $app): CertificateValidator {
            $configured = $app->make('config')->get('eidas-cert-auth.aia_cache_store');
            $cache = $app->make(CacheFactory::class)->store(is_string($configured) && $configured !== '' ? $configured : null);

            return new CertificateValidator(new CertificateParser(), $app->make(TrustStore::class), new RevocationChecker(new CurlTransport(true), $app->make(RevocationCache::class)), $app->make(Options::class), intermediates: array_values(array_filter((array) $app->make('config')->get('eidas-cert-auth.intermediates', []), 'is_string')), aiaCacheStore: new LaravelAiaCache($cache));
        });
        $this->app->alias(CertificateValidator::class, 'eidas-cert-auth');
    }

    public function boot(): void
    {
        if ($this->app->bound('router')) {
            $router = $this->app->make('router');
            if (is_object($router) && method_exists($router, 'aliasMiddleware')) {
                $router->aliasMiddleware('eidas.cert', ValidateClientCertificate::class);
            }
        }
        if ($this->app->runningInConsole()) {
            $this->publishes([__DIR__ . '/../../config/eidas-cert-auth.php' => $this->app->configPath('eidas-cert-auth.php')], 'eidas-cert-auth-config');
            $this->commands([TrustListUpdateCommand::class, DoctorCommand::class]);
        }
        if ((bool) $this->app->make('config')->get('eidas-cert-auth.schedule_daily', true)) {
            $this->app->afterResolving(Schedule::class, static function (Schedule $schedule): void {
                $schedule->command('eidas:trust-list:update')->daily();
            });
        }
    }
}
