<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Transport;

use Iberfacil\EidasCertAuth\Contracts\Transport;
use Iberfacil\EidasCertAuth\Exceptions\EidasCertAuthException;

final class FakeTransport implements Transport
{
    /** @var array<string, string> */
    private array $responses = [];

    /** @var list<array{method: string, url: string, timeout: int}> */
    public array $sent = [];

    public function respond(string $url, string $body): self
    {
        $this->responses[$url] = $body;

        return $this;
    }

    public function get(string $url, int $timeoutSeconds): string
    {
        $this->sent[] = ['method' => 'GET', 'url' => $url, 'timeout' => $timeoutSeconds];

        return $this->response($url);
    }

    public function post(string $url, string $body, string $contentType, int $timeoutSeconds): string
    {
        $this->sent[] = ['method' => 'POST', 'url' => $url, 'timeout' => $timeoutSeconds];

        return $this->response($url);
    }

    private function response(string $url): string
    {
        if (! array_key_exists($url, $this->responses)) {
            throw new EidasCertAuthException('No fake response for ' . $url);
        }

        return $this->responses[$url];
    }
}
