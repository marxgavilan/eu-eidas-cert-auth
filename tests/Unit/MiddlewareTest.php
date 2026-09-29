<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use Iberfacil\EidasCertAuth\Cache\InMemoryRevocationCache;
use Iberfacil\EidasCertAuth\Certificate\CertificateParser;
use Iberfacil\EidasCertAuth\Certificate\CertificateValidator;
use Iberfacil\EidasCertAuth\Certificate\RevocationChecker;
use Iberfacil\EidasCertAuth\Laravel\Middleware\ValidateClientCertificate;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Tests\Support\TestPki;
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
    public function testValidServerPemEscapedAndTabbedFormatsReachProtectedRoute(): void
    {
        $pki = new TestPki();
        $root = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $client = $pki->issue(['CN' => 'Citizen', 'serialNumber' => 'IDCES-00000000T', 'C' => 'ES'], $root, 'client');
        $dir = sys_get_temp_dir() . '/eidas-middleware-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        $store = new TrustStore($dir . '/trust');
        $store->publish([hash('sha256', TestPki::der($root['pem'])) => ['pem' => $root['pem'], 'country' => 'ES', 'service' => 'CA/QC']]);
        $transport = (new FakeTransport())->respond('http://ocsp.example.test/response', $pki->ocspResponse($client['pem'], $root));
        $validator = new CertificateValidator(new CertificateParser(), $store, new RevocationChecker($transport, new InMemoryRevocationCache()), new Options());
        $middleware = new ValidateClientCertificate($validator, static fn(string $key, mixed $default = null): mixed => $default);
        try {
            foreach ([$client['pem'], rawurlencode($client['pem']), str_replace("\n", "\n\t", rtrim($client['pem']))] as $pem) {
                $request = Request::create('/certificate-login', 'GET', [], [], [], ['SSL_CLIENT_CERT' => $pem]);
                self::assertSame('reached', $middleware->handle($request, static fn(Request $request): string => $request->attributes->has('eidas.identity') ? 'reached' : 'missing'));
            }
        } finally {
            foreach (glob($dir . '/.trust.*') ?: [] as $generation) {
                if (is_dir($generation)) {
                    foreach (glob($generation . '/*') ?: [] as $file) {
                        unlink($file);
                    }
                    rmdir($generation);
                } else {
                    unlink($generation);
                }
            }
            unlink($dir . '/trust');
            rmdir($dir);
        }
    }
    public function testHttpPrefixedServerVariableIsAlwaysRejected(): void
    {
        $validator = new CertificateValidator(new CertificateParser(), new TrustStore('/tmp/missing-eidas-middleware-store'), new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options());
        $middleware = new ValidateClientCertificate($validator, static fn(string $key, mixed $default = null): mixed => $key === 'eidas-cert-auth.server_variable' ? 'HTTP_SSL_CLIENT_CERT' : $default);
        $request = Request::create('/certificate-login', 'GET', [], [], [], ['HTTP_SSL_CLIENT_CERT' => 'forged']);
        $this->expectExceptionMessage('Invalid certificate server variable.');
        $middleware->handle($request, static fn(): null => null);
    }

    public function testTrustedProxyWithoutCertificateHeaderIsRejected(): void
    {
        $validator = new CertificateValidator(new CertificateParser(), new TrustStore('/tmp/missing-eidas-middleware-store'), new RevocationChecker(new FakeTransport(), new InMemoryRevocationCache()), new Options());
        $middleware = new ValidateClientCertificate($validator, static fn(string $key, mixed $default = null): mixed => match ($key) {
            'eidas-cert-auth.trusted_proxy_header' => 'X-SSL-Client-Cert',
            'eidas-cert-auth.trusted_proxy_ips' => ['203.0.113.10'],
            default => $default,
        });
        $request = Request::create('/certificate-login', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.10']);
        $this->expectExceptionMessage('A client certificate is required.');
        $middleware->handle($request, static fn(): null => null);
    }

}
