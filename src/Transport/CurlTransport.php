<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Transport;

use Iberfacil\EidasCertAuth\Contracts\Transport;
use Iberfacil\EidasCertAuth\Exceptions\EidasCertAuthException;

final class CurlTransport implements Transport
{
    public function __construct(private readonly bool $allowHttp = false) {}

    public function get(string $url, int $timeoutSeconds): string
    {
        return $this->request($url, null, null, $timeoutSeconds);
    }

    public function post(string $url, string $body, string $contentType, int $timeoutSeconds): string
    {
        return $this->request($url, $body, $contentType, $timeoutSeconds);
    }

    private function request(string $url, ?string $body, ?string $contentType, int $timeoutSeconds): string
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $host = parse_url($url, PHP_URL_HOST);
        if (filter_var($url, FILTER_VALIDATE_URL) === false || ! is_string($host) || ($scheme !== 'https' && ! ($this->allowHttp && $scheme === 'http')) || strtolower($host) === 'localhost' || ! str_contains($host, '.') || (filter_var($host, FILTER_VALIDATE_IP) !== false && filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false)) {
            throw new EidasCertAuthException('The URL is not an allowed public HTTP endpoint.');
        }
        $curl = curl_init($url);
        if ($curl === false) {
            throw new EidasCertAuthException('Cannot initialize HTTP transport.');
        }
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_TIMEOUT => max(1, $timeoutSeconds),
            CURLOPT_CONNECTTIMEOUT => min(5, max(1, $timeoutSeconds)),
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_POST => $body !== null,
            CURLOPT_HTTPHEADER => $contentType === null ? [] : ['Content-Type: ' . $contentType, 'Accept: application/ocsp-response'],
        ]);
        if ($this->allowHttp) {
            $port = parse_url($url, PHP_URL_PORT) ?: ($scheme === 'https' ? 443 : 80);
            $addresses = filter_var($host, FILTER_VALIDATE_IP) !== false ? [$host] : $this->publicAddresses($host);
            if ($addresses === []) {
                curl_close($curl);
                throw new EidasCertAuthException('The revocation host has no public address.');
            }
            curl_setopt($curl, CURLOPT_RESOLVE, [$host . ':' . $port . ':' . $addresses[0]]);
        }
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            curl_setopt($curl, constant('CURLOPT_PROTOCOLS_STR'), $this->allowHttp ? 'http,https' : 'https');
        } else {
            curl_setopt($curl, CURLOPT_PROTOCOLS, $this->allowHttp ? CURLPROTO_HTTP | CURLPROTO_HTTPS : CURLPROTO_HTTPS);
        }
        if ($body !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }
        $result = curl_exec($curl);
        $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);
        if (! is_string($result) || $status !== 200 || strlen($result) > 20_000_000) {
            throw new EidasCertAuthException('HTTP download failed or exceeded the size limit.');
        }

        return $result;
    }

    /** @return list<string> */
    private function publicAddresses(string $host): array
    {
        $records = dns_get_record($host, DNS_A | DNS_AAAA);
        if (! is_array($records) || $records === []) {
            return [];
        }
        $addresses = [];
        foreach ($records as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;
            if (! is_string($address) || filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return [];
            }
            $addresses[] = str_contains($address, ':') ? '[' . $address . ']' : $address;
        }

        return $addresses;
    }
}
