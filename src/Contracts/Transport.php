<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Contracts;

interface Transport
{
    public function get(string $url, int $timeoutSeconds): string;

    public function post(string $url, string $body, string $contentType, int $timeoutSeconds): string;
}
