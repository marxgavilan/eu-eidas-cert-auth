<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Transport;

use CurlHandle;

final class CurlStubState
{
    public static bool $simulateRedirect = false;

    public static ?bool $followLocation = null;
}

/** @return array<int, array<string, string>>|false */
function dns_get_record(string $host, int $type): array|false
{
    if ($host === 'private.example.test') {
        return [['type' => 'A', 'ip' => '127.0.0.1']];
    }
    if ($host === 'redirect.example.test') {
        return [['type' => 'A', 'ip' => '8.8.8.8']];
    }

    return \dns_get_record($host, $type);
}

/** @param array<int, mixed> $options */
function curl_setopt_array(CurlHandle $handle, array $options): bool
{
    if (CurlStubState::$simulateRedirect) {
        CurlStubState::$followLocation = $options[CURLOPT_FOLLOWLOCATION] ?? null;
    }

    return \curl_setopt_array($handle, $options);
}

function curl_exec(CurlHandle $handle): string|bool
{
    return CurlStubState::$simulateRedirect ? true : \curl_exec($handle);
}

function curl_getinfo(CurlHandle $handle, int $option = 0): mixed
{
    return CurlStubState::$simulateRedirect && $option === CURLINFO_RESPONSE_CODE ? 302 : \curl_getinfo($handle, $option);
}
