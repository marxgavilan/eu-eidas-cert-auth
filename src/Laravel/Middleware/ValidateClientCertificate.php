<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Laravel\Middleware;

use Closure;
use Iberfacil\EidasCertAuth\Certificate\CertificateValidator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

final readonly class ValidateClientCertificate
{
    public function __construct(private CertificateValidator $validator, private ?Closure $configuration = null) {}

    public function handle(Request $request, Closure $next): mixed
    {
        $serverKey = (string) $this->setting('eidas-cert-auth.server_variable', 'SSL_CLIENT_CERT');
        if ($serverKey === '' || str_starts_with(strtoupper($serverKey), 'HTTP_')) {
            throw new AccessDeniedHttpException('Invalid certificate server variable.');
        }
        $pem = $request->server($serverKey);
        if ((! is_string($pem) || $pem === '') && $this->trustedProxy($request)) {
            $header = $this->setting('eidas-cert-auth.trusted_proxy_header');
            $pem = is_string($header) && $header !== '' ? $request->headers->get($header) : null;
        }
        if (! is_string($pem) || $pem === '') {
            throw new AccessDeniedHttpException('A client certificate is required.');
        }
        $result = $this->validator->validate($pem);
        if (! $result->valid) {
            throw new AccessDeniedHttpException('Client certificate rejected: ' . $result->reason);
        }
        $request->attributes->set('eidas.identity', $result->identity);
        $request->attributes->set('eidas.validation', $result);

        return $next($request);
    }

    private function trustedProxy(Request $request): bool
    {
        $remote = $request->server('REMOTE_ADDR');
        $ips = $this->setting('eidas-cert-auth.trusted_proxy_ips', []);

        return is_string($remote) && is_array($ips) && in_array($remote, $ips, true);
    }

    private function setting(string $key, mixed $default = null): mixed
    {
        return $this->configuration === null ? Config::get($key, $default) : ($this->configuration)($key, $default);
    }
}
