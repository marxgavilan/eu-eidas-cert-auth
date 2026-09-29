<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Trust;

use DateTimeImmutable;
use DOMDocument;
use DOMElement;
use DOMXPath;
use Iberfacil\EidasCertAuth\Contracts\Transport;
use Iberfacil\EidasCertAuth\Data\ImportResult;
use Iberfacil\EidasCertAuth\Exceptions\TrustListRejected;
use Iberfacil\EidasCertAuth\Options;

final readonly class TrustListImporter
{
    public function __construct(private Transport $transport, private XmlSignatureVerifier $signatures, private TrustStore $store, private Options $options) {}

    public function importLotl(?string $xml = null, bool $force = false, bool $dryRun = false, ?DateTimeImmutable $at = null): ImportResult
    {
        $document = $this->signatures->verify($xml ?? $this->transport->get(Options::LOTL_URL, $this->options->timeoutSeconds), $this->options->lotlSignerFingerprints);
        $this->assertFresh($document, $at ?? new DateTimeImmutable());
        $xpath = new DOMXPath($document);
        $certificates = [];
        $found = [];
        foreach ($xpath->query('//*[local-name()="OtherTSLPointer"]') ?: [] as $pointer) {
            if (! $pointer instanceof DOMElement) {
                continue;
            }
            $country = strtoupper(trim((string) $xpath->evaluate('string(.//*[local-name()="SchemeTerritory"][1])', $pointer)));
            if (! in_array($country, $this->options->acceptedCountries(), true)) {
                continue;
            }
            $url = trim((string) $xpath->evaluate('string(./*[local-name()="TSLLocation"][1])', $pointer));
            $mime = trim((string) $xpath->evaluate('string(.//*[local-name()="MimeType"][1])', $pointer));
            if ($mime !== '' && $mime !== 'application/vnd.etsi.tsl+xml') {
                continue;
            }
            if ($mime === '' && ! str_ends_with(strtolower((string) parse_url($url, PHP_URL_PATH)), '.xml')) {
                continue;
            }
            if ($url === '' || ! str_starts_with($url, 'https://') || isset($found[$country])) {
                throw new TrustListRejected('Missing, duplicate or unsafe national TSL pointer.');
            }
            $found[$country] = true;
            $signers = self::fingerprints($xpath, $pointer);
            if ($signers === []) {
                throw new TrustListRejected('The LOTL did not announce national TSL signers.');
            }
            $tsl = $this->signatures->verify($this->transport->get($url, $this->options->timeoutSeconds), $signers);
            $this->assertFresh($tsl, $at ?? new DateTimeImmutable());
            $this->assertCountry($tsl, $country);
            $certificates += $this->extract($tsl, $country, $at ?? new DateTimeImmutable());
        }
        foreach ($this->options->acceptedCountries() as $country) {
            if (! isset($found[$country])) {
                throw new TrustListRejected('An accepted country is missing from the LOTL.');
            }
        }

        return $this->store->publish($certificates, $force, $dryRun);
    }

    /** @param list<string> $signerFingerprints */
    public function importTsl(string $xml, string $country, array $signerFingerprints, bool $force = false, bool $dryRun = false, ?DateTimeImmutable $at = null): ImportResult
    {
        if (! in_array($country, $this->options->acceptedCountries(), true)) {
            throw new TrustListRejected('The country is not accepted.');
        }
        $document = $this->signatures->verify($xml, $signerFingerprints);
        $this->assertFresh($document, $at ?? new DateTimeImmutable());
        $this->assertCountry($document, $country);

        return $this->store->publish($this->extract($document, $country, $at ?? new DateTimeImmutable()), $force, $dryRun);
    }

    /** @return array<string, array{pem: string, country: string, service: string}> */
    private function extract(DOMDocument $document, string $country, DateTimeImmutable $at): array
    {
        $xpath = new DOMXPath($document);
        $result = [];
        foreach ($xpath->query('//*[local-name()="TSPService"]') ?: [] as $service) {
            if (! $service instanceof DOMElement) {
                continue;
            }
            $infos = $xpath->query('./*[local-name()="ServiceInformation"]', $service);
            $info = $infos === false ? null : $infos->item(0);
            if (! $info instanceof DOMElement) {
                continue;
            }
            $type = trim((string) $xpath->evaluate('string(./*[local-name()="ServiceTypeIdentifier"][1])', $info));
            if (! in_array($type, $this->options->serviceTypes, true) || ! $this->isGranted($xpath, $service, $at)) {
                continue;
            }
            foreach ($xpath->query('./*[local-name()="ServiceDigitalIdentity"]//*[local-name()="X509Certificate"]', $info) ?: [] as $node) {
                if (! $node instanceof DOMElement) {
                    continue;
                }
                $der = base64_decode(preg_replace('/\s+/', '', $node->textContent) ?? '', true);
                if (! is_string($der)) {
                    throw new TrustListRejected('Invalid CA certificate in the TSL.');
                }
                $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
                $details = @openssl_x509_parse($pem);
                if (! is_array($details) || ! str_contains((string) ($details['extensions']['basicConstraints'] ?? ''), 'CA:TRUE')) {
                    continue;
                }
                $result[hash('sha256', $der)] = ['pem' => $pem, 'country' => $country, 'service' => $type];
            }
        }

        return $result;
    }

    private function isGranted(DOMXPath $xpath, DOMElement $service, DateTimeImmutable $at): bool
    {
        $states = [];
        foreach (['./*[local-name()="ServiceInformation"]', './*[local-name()="ServiceHistory"]/*[local-name()="ServiceHistoryInstance"]'] as $query) {
            foreach ($xpath->query($query, $service) ?: [] as $node) {
                if (! $node instanceof DOMElement) {
                    continue;
                }
                $start = trim((string) $xpath->evaluate('string(./*[local-name()="StatusStartingTime"][1])', $node));
                $status = trim((string) $xpath->evaluate('string(./*[local-name()="ServiceStatus"][1])', $node));
                try {
                    $date = new DateTimeImmutable($start);
                } catch (\Throwable) {
                    continue;
                }
                if ($date <= $at) {
                    $states[$date->format('U.u')] = $status;
                }
            }
        }
        if ($states === []) {
            return false;
        }
        ksort($states);
        $latest = end($states);

        return is_string($latest) && str_ends_with($latest, '/granted');
    }

    private function assertFresh(DOMDocument $document, DateTimeImmutable $at): void
    {
        $xpath = new DOMXPath($document);
        $next = trim((string) $xpath->evaluate('string(/*/*[local-name()="SchemeInformation"]/*[local-name()="NextUpdate"]/*[local-name()="dateTime"][1])'));
        if ($next !== '' && new DateTimeImmutable($next) <= $at) {
            throw new TrustListRejected('The trusted list has expired.');
        }
    }

    private function assertCountry(DOMDocument $document, string $country): void
    {
        $xpath = new DOMXPath($document);
        $actual = trim((string) $xpath->evaluate('string(/*/*[local-name()="SchemeInformation"]/*[local-name()="SchemeTerritory"][1])'));
        if ($actual !== $country) {
            throw new TrustListRejected('National TSL territory does not match the LOTL pointer.');
        }
    }

    /** @return list<string> */
    private static function fingerprints(DOMXPath $xpath, DOMElement $pointer): array
    {
        $result = [];
        foreach ($xpath->query('./*[local-name()="ServiceDigitalIdentities"]//*[local-name()="X509Certificate"]', $pointer) ?: [] as $node) {
            if (! $node instanceof DOMElement) {
                continue;
            }
            $der = base64_decode(preg_replace('/\s+/', '', $node->textContent) ?? '', true);
            if (is_string($der)) {
                $result[] = hash('sha256', $der);
            }
        }

        return array_values(array_unique($result));
    }
}
