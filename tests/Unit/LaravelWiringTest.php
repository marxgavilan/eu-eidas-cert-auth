<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use Iberfacil\EidasCertAuth\Cache\InMemoryRevocationCache;
use Iberfacil\EidasCertAuth\Certificate\CertificateValidator;
use Iberfacil\EidasCertAuth\Contracts\RevocationCache;
use Iberfacil\EidasCertAuth\Laravel\EidasCertAuthServiceProvider;
use Iberfacil\EidasCertAuth\Laravel\Middleware\ValidateClientCertificate;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class LaravelWiringTest extends TestCase
{
    public function testProviderRegistersNamedMiddlewareAlias(): void
    {
        $router = new class {
            /** @var array<string, string> */
            public array $aliases = [];

            public function aliasMiddleware(string $name, string $class): void
            {
                $this->aliases[$name] = $class;
            }
        };
        $config = new class {
            public function get(string $key, mixed $default = null): mixed
            {
                return $key === 'eidas-cert-auth.schedule_daily' ? false : $default;
            }
        };
        $app = $this->createMock(Application::class);
        $app->method('bound')->with('router')->willReturn(true);
        $app->method('make')->willReturnCallback(static fn(string $abstract): mixed => $abstract === 'router' ? $router : $config);
        $app->method('runningInConsole')->willReturn(false);
        (new EidasCertAuthServiceProvider($app))->boot();
        self::assertSame(ValidateClientCertificate::class, $router->aliases['eidas.cert']);
    }

    public function testDailyScheduleAndThirtyDayStoreAgeAreDefaults(): void
    {
        self::assertSame(2592000, (new Options())->maximumStoreAgeSeconds);
        $configRepository = new class {
            public function get(string $key, mixed $default = null): mixed
            {
                return $default;
            }
        };
        $callback = null;
        $app = $this->createMock(Application::class);
        $app->method('runningInConsole')->willReturn(false);
        $app->method('make')->with('config')->willReturn($configRepository);
        $app->expects(self::once())->method('afterResolving')->with(Schedule::class, self::isInstanceOf(\Closure::class))->willReturnCallback(static function (string $abstract, \Closure $resolver) use (&$callback): void {
            $callback = $resolver;
        });
        (new EidasCertAuthServiceProvider($app))->boot();
        self::assertInstanceOf(\Closure::class, $callback);
        $event = $this->createMock(Event::class);
        $event->expects(self::once())->method('daily');
        $schedule = $this->createMock(Schedule::class);
        $schedule->expects(self::once())->method('command')->with('eidas:trust-list:update')->willReturn($event);
        $callback($schedule);
    }

    public function testProviderPassesSecurityOptionsAndIntermediatesToValidator(): void
    {
        $values = [
            'eidas-cert-auth.region' => 'ES',
            'eidas-cert-auth.countries' => ['ES', 'PT'],
            'eidas-cert-auth.service_types' => ['http://uri.etsi.org/TrstSvc/Svctype/CA/QC'],
            'eidas-cert-auth.require_fore_signatures' => true,
            'eidas-cert-auth.maximum_store_age_seconds' => 12345,
            'eidas-cert-auth.intermediates' => ['test-intermediate'],
            'eidas-cert-auth.authentication_policies' => ['ES' => ['2.16.724.1.2.2.2.4']],
            'eidas-cert-auth.profiles' => ['signature' => ['qualified_required' => true, 'dnie' => false, 'usage' => 'signature']],
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
        $cacheRepository = $this->createMock(Repository::class);
        $cacheFactory = $this->createMock(CacheFactory::class);
        $cacheFactory->method('store')->willReturn($cacheRepository);
        $app->method('make')->willReturnCallback(static function (string $abstract) use ($config, &$options, $cacheFactory): mixed {
            return match ($abstract) {
                'config' => $config,
                Options::class => $options,
                TrustStore::class => new TrustStore('/tmp/nonexistent-eidas-wiring'),
                RevocationCache::class => new InMemoryRevocationCache(),
                CacheFactory::class => $cacheFactory,
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
        self::assertSame(['ES' => ['2.16.724.1.2.2.2.4']], $options->authenticationPolicies);
        self::assertTrue($options->profile('signature')->qualifiedRequired);
        self::assertFalse($options->profile('signature')->dnie);
        self::assertSame('signature', $options->profile('signature')->usage);
        self::assertSame('authentication', $options->profile()->usage);
        $validator = $bindings[CertificateValidator::class]($app);
        self::assertInstanceOf(CertificateValidator::class, $validator);
        self::assertSame(['test-intermediate'], (new \ReflectionProperty($validator, 'intermediates'))->getValue($validator));
    }

    public function testInvalidProfilesJsonFailsWhenOptionsAreUsedNotAtRegistration(): void
    {
        $config = new class {
            public function get(string $key, mixed $default = null): mixed
            {
                return $key === 'eidas-cert-auth.profiles' ? '{invalid' : $default;
            }
        };
        $bindings = [];
        $app = $this->createMockForIntersectionOfInterfaces([Application::class, CachesConfiguration::class]);
        self::assertInstanceOf(Application::class, $app);
        $app->method('configurationIsCached')->willReturn(true);
        $app->method('singleton')->willReturnCallback(static function (string $abstract, mixed $factory) use (&$bindings): void {
            $bindings[$abstract] = $factory;
        });
        $app->method('make')->with('config')->willReturn($config);
        (new EidasCertAuthServiceProvider($app))->register();
        self::assertArrayHasKey(Options::class, $bindings);
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid EIDAS_PROFILES JSON');
        $bindings[Options::class]($app);
    }
}
