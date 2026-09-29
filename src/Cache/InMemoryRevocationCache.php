<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Cache;

use Iberfacil\EidasCertAuth\Contracts\RevocationCache;

final class InMemoryRevocationCache implements RevocationCache
{
    /** @var array<string, array{status: string, source: string, expires: int}> */
    private array $values = [];

    public function get(string $fingerprint): ?array
    {
        $entry = $this->values[$fingerprint] ?? null;
        if ($entry === null || $entry['expires'] <= time()) {
            return null;
        }

        return ['status' => $entry['status'], 'source' => 'cache:' . $entry['source']];
    }

    public function put(string $fingerprint, string $status, string $source, int $ttlSeconds): void
    {
        $this->values[$fingerprint] = ['status' => $status, 'source' => $source, 'expires' => time() + max(1, $ttlSeconds)];
    }
}
