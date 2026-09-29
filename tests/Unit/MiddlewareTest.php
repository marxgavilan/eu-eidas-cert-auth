<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use Iberfacil\EidasCertAuth\Cache\InMemoryRevocationCache;
use Iberfacil\EidasCertAuth\Certificate\CertificateParser;
use Iberfacil\EidasCertAuth\Certificate\CertificateValidator;
use Iberfacil\EidasCertAuth\Certificate\RevocationChecker;
use Iberfacil\EidasCertAuth\Laravel\Middleware\ValidateClientCertificate;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Transport\FakeTransport;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

final class MiddlewareTest extends TestCase
{
    public function testBrowserHeaderIsIgnoredUnlessProxyAddressAndHeaderAreConfigured(): void
    {
        $config = new class {
            /** @var array<string, mixed> */
            public array $values = [];

            public function get(string $key, mixed $default = null): mixed
            {
                return $this->values[$key] ?? $default;
            }
        };
        $middleware = new ValidateClientCertificate(new CertificateValidator(new CertificateParser(), new TrustStore('/tmp/missing-eidas-test-store'), new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options()), static fn(string $key, mixed $default = null): mixed => $config->get($key, $default));
        $testAddress = inet_ntop(pack('C4', 203, 0, 113, 10));
        self::assertIsString($testAddress);
        $request = Request::create('/certificate-login', 'GET', [], [], [], ['REMOTE_ADDR' => $testAddress]);
        $request->headers->set('X-SSL-Client-Cert', 'browser-forged');

        try {
            $middleware->handle($request, static fn(): null => null);
            self::fail('A browser header must be ignored.');
        } catch (AccessDeniedHttpException $exception) {
            self::assertSame('A client certificate is required.', $exception->getMessage());
        }

        $config->values['eidas-cert-auth.trusted_proxy_header'] = 'X-SSL-Client-Cert';
        $config->values['eidas-cert-auth.trusted_proxy_ips'] = [$testAddress];
        $this->expectExceptionMessage('Client certificate rejected: malformed');
        $middleware->handle($request, static fn(): null => null);
    }
}
