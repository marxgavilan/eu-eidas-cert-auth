<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Laravel;

use Iberfacil\EidasCertAuth\Contracts\RevocationCache;
use Illuminate\Contracts\Cache\Repository;

final readonly class LaravelRevocationCache implements RevocationCache
{
    public function __construct(private Repository $cache) {}

    public function get(string $fingerprint): ?array
    {
        $value = $this->cache->get(self::key($fingerprint));
        if (! is_array($value) || ! in_array($value['status'] ?? null, ['good', 'revoked'], true) || ! is_string($value['source'] ?? null)) {
            return null;
        }

        return ['status' => $value['status'], 'source' => 'cache:' . $value['source']];
    }

    public function put(string $fingerprint, string $status, string $source, int $ttlSeconds): void
    {
        $this->cache->put(self::key($fingerprint), ['status' => $status, 'source' => $source], $ttlSeconds);
    }

    private static function key(string $fingerprint): string
    {
        return 'eidas:revocation:' . strtolower($fingerprint);
    }
}
