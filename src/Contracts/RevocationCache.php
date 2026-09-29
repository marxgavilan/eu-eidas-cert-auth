<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Contracts;

interface RevocationCache
{
    /** @return array{status: string, source: string}|null */
    public function get(string $fingerprint): ?array;

    public function put(string $fingerprint, string $status, string $source, int $ttlSeconds): void;
}
