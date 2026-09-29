<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use Iberfacil\EidasCertAuth\Exceptions\EidasCertAuthException;
use Iberfacil\EidasCertAuth\Transport\CurlStubState;
use Iberfacil\EidasCertAuth\Transport\CurlTransport;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Support/TransportDnsStub.php';

final class CurlTransportPolicyTest extends TestCase
{
    public function testUnsafeSchemesAddressesAndPortsFailBeforeNetworkAccess(): void
    {
        $rejected = 0;
        foreach (['http://example.test/x', 'https://localhost/x', 'https://127.0.0.1/x', 'https://192.168.1.1/x', 'https://100.64.0.1/x', 'https://private.example.test/x', 'https://169.254.1.1/x', 'https://example.test:8443/x', 'file:///etc/passwd'] as $url) {
            try {
                (new CurlTransport())->get($url, 1);
                self::fail($url . ' was accepted.');
            } catch (EidasCertAuthException) {
                $rejected++;
            }
        }
        foreach (['http://127.0.0.1/x', 'http://100.64.0.1/x', 'http://192.168.1.1/x'] as $url) {
            try {
                (new CurlTransport(true))->get($url, 1);
                self::fail($url . ' was accepted.');
            } catch (EidasCertAuthException) {
                $rejected++;
            }
        }
        self::assertSame(12, $rejected);
    }

    public function testRedirectResponseIsRejectedWithoutFollowingIt(): void
    {
        CurlStubState::$simulateRedirect = true;
        CurlStubState::$followLocation = null;
        try {
            (new CurlTransport())->get('https://redirect.example.test/x', 1);
            self::fail('HTTP redirect was accepted.');
        } catch (EidasCertAuthException) {
            self::assertFalse(CurlStubState::$followLocation);
        } finally {
            CurlStubState::$simulateRedirect = false;
            CurlStubState::$followLocation = null;
        }
    }

}
