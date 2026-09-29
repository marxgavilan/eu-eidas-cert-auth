<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use Iberfacil\EidasCertAuth\Cache\InMemoryRevocationCache;
use Iberfacil\EidasCertAuth\Certificate\CertificateValidator;
use Iberfacil\EidasCertAuth\Contracts\RevocationCache;
use Iberfacil\EidasCertAuth\Laravel\EidasCertAuthServiceProvider;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use PHPUnit\Framework\TestCase;

final class LaravelWiringTest extends TestCase
{
    public function testProviderPassesSecurityOptionsAndIntermediatesToValidator(): void
    {
        $values = [
            'eidas-cert-auth.region' => 'ES',
            'eidas-cert-auth.countries' => ['ES', 'PT'],
            'eidas-cert-auth.service_types' => ['http://uri.etsi.org/TrstSvc/Svctype/CA/QC'],
            'eidas-cert-auth.require_fore_signatures' => true,
            'eidas-cert-auth.maximum_store_age_seconds' => 12345,
            'eidas-cert-auth.intermediates' => ['test-intermediate'],
        ];
        $config = new class ($values) {
            /** @param array<string, mixed> $values */
            public function __construct(private array $values) {}

            public function get(string $key, mixed $default = null): mixed
            {
                return $this->values[$key] ?? $default;
            }
        };
        $bindings = [];
        $options = null;
        $app = $this->createMockForIntersectionOfInterfaces([Application::class, CachesConfiguration::class]);
        self::assertInstanceOf(Application::class, $app);
        $app->method('configurationIsCached')->willReturn(true);
        $app->method('singleton')->willReturnCallback(static function (string $abstract, mixed $factory) use (&$bindings): void {
            $bindings[$abstract] = $factory;
        });
        $app->method('make')->willReturnCallback(static function (string $abstract) use ($config, &$options): mixed {
            return match ($abstract) {
                'config' => $config,
                Options::class => $options,
                TrustStore::class => new TrustStore('/tmp/nonexistent-eidas-wiring'),
                RevocationCache::class => new InMemoryRevocationCache(),
                default => null,
            };
        });
        (new EidasCertAuthServiceProvider($app))->register();
        self::assertArrayHasKey(Options::class, $bindings);
        self::assertArrayHasKey(CertificateValidator::class, $bindings);
        $options = $bindings[Options::class]($app);
        self::assertInstanceOf(Options::class, $options);
        self::assertSame(['ES', 'PT'], $options->acceptedCountries());
        self::assertSame(12345, $options->maximumStoreAgeSeconds);
        self::assertTrue($options->requireForeSignatures);
        $validator = $bindings[CertificateValidator::class]($app);
        self::assertInstanceOf(CertificateValidator::class, $validator);
        self::assertSame(['test-intermediate'], (new \ReflectionProperty($validator, 'intermediates'))->getValue($validator));
    }
}
