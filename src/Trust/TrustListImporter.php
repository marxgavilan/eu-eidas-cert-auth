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
use Throwable;

final readonly class TrustListImporter
{
    private const TSL = 'http://uri.etsi.org/02231/v2#';

    private const SIE = 'http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#';

    public function __construct(private Transport $transport, private XmlSignatureVerifier $signatures, private TrustStore $store, private Options $options) {}

    public function importLotl(?string $xml = null, bool $force = false, bool $dryRun = false, ?DateTimeImmutable $at = null): ImportResult
    {
        $at ??= new DateTimeImmutable();
        $document = $this->signatures->verify($xml ?? $this->transport->get(Options::LOTL_URL, $this->options->timeoutSeconds), $this->options->lotlSignerFingerprints);
        $nextUpdate = $this->assertFresh($document, $at);
        $sequences = ['EU' => $this->sequence($document)];
        $issueDates = ['EU' => $this->issueDate($document)];
        $xpath = self::xpath($document);
        $certificates = [];
        $found = [];
        foreach ($xpath->query('/tsl:TrustServiceStatusList/tsl:SchemeInformation/tsl:PointersToOtherTSL/tsl:OtherTSLPointer') ?: [] as $pointer) {
            if (! $pointer instanceof DOMElement) {
                continue;
            }
            $country = strtoupper(trim((string) $xpath->evaluate('string(./tsl:AdditionalInformation/tsl:OtherInformation/tsl:SchemeTerritory[1])', $pointer)));
            if (! in_array($country, $this->options->acceptedCountries(), true)) {
                continue;
            }
            $url = trim((string) $xpath->evaluate('string(./tsl:TSLLocation[1])', $pointer));
            $mime = trim((string) $xpath->evaluate('string(./tsl:AdditionalInformation/tsl:OtherInformation/tsl:MimeType[1])', $pointer));
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
            $tslNext = $this->assertFresh($tsl, $at);
            if ($tslNext < $nextUpdate) {
                $nextUpdate = $tslNext;
            }
            $this->assertCountry($tsl, $country);
            $sequences[$country] = $this->sequence($tsl);
            $issueDates[$country] = $this->issueDate($tsl);
            $certificates += $this->extract($tsl, $country, $at);
        }
        foreach ($this->options->acceptedCountries() as $country) {
            if (! isset($found[$country])) {
                throw new TrustListRejected('An accepted country is missing from the LOTL.');
            }
        }

        return $this->store->publish($certificates, $force, $dryRun, $sequences, $nextUpdate, $issueDates);
    }

    /** @param list<string> $signerFingerprints */
    public function importTsl(string $xml, string $country, array $signerFingerprints, bool $force = false, bool $dryRun = false, ?DateTimeImmutable $at = null): ImportResult
    {
        if (! in_array($country, $this->options->acceptedCountries(), true)) {
            throw new TrustListRejected('The country is not accepted.');
        }
        $at ??= new DateTimeImmutable();
        $document = $this->signatures->verify($xml, $signerFingerprints);
        $next = $this->assertFresh($document, $at);
        $this->assertCountry($document, $country);

        return $this->store->publish($this->extract($document, $country, $at), $force, $dryRun, [$country => $this->sequence($document)], $next, [$country => $this->issueDate($document)]);
    }

    /** @return array<string, array{pem: string, country: string, service: string}> */
    private function extract(DOMDocument $document, string $country, DateTimeImmutable $at): array
    {
        $xpath = self::xpath($document);
        $result = [];
        foreach ($xpath->query('/tsl:TrustServiceStatusList/tsl:TrustServiceProviderList/tsl:TrustServiceProvider/tsl:TSPServices/tsl:TSPService') ?: [] as $service) {
            if (! $service instanceof DOMElement) {
                continue;
            }
            $infos = $xpath->query('./tsl:ServiceInformation', $service);
            $info = $infos === false ? null : $infos->item(0);
            if (! $info instanceof DOMElement) {
                continue;
            }
            $type = trim((string) $xpath->evaluate('string(./tsl:ServiceTypeIdentifier[1])', $info));
            if (! in_array($type, $this->options->serviceTypes, true) || ! $this->isGranted($xpath, $service, $at) || ! $this->hasForeSignatures($xpath, $info)) {
                continue;
            }
            foreach ($xpath->query('./tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate', $info) ?: [] as $node) {
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

    private function hasForeSignatures(DOMXPath $xpath, DOMElement $info): bool
    {
        $uri = 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures';
        $fore = false;
        foreach ($xpath->query('./tsl:ServiceInformationExtensions/tsl:Extension/tsl:AdditionalServiceInformation/tsl:URI', $info) ?: [] as $node) {
            if (! $node instanceof DOMElement) {
                continue;
            }
            if (trim($node->textContent) === $uri) {
                $fore = true;
            }
        }

        return ! $this->options->requireForeSignatures || $fore;
    }

    private function isGranted(DOMXPath $xpath, DOMElement $service, DateTimeImmutable $at): bool
    {
        $states = [];
        foreach (['./tsl:ServiceInformation', './tsl:ServiceHistory/tsl:ServiceHistoryInstance'] as $query) {
            foreach ($xpath->query($query, $service) ?: [] as $node) {
                if (! $node instanceof DOMElement) {
                    continue;
                }
                $start = trim((string) $xpath->evaluate('string(./tsl:StatusStartingTime[1])', $node));
                $status = trim((string) $xpath->evaluate('string(./tsl:ServiceStatus[1])', $node));
                try {
                    $date = new DateTimeImmutable($start);
                } catch (Throwable) {
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

    private function assertFresh(DOMDocument $document, DateTimeImmutable $at): DateTimeImmutable
    {
        $xpath = self::xpath($document);
        $next = trim((string) $xpath->evaluate('string(/tsl:TrustServiceStatusList/tsl:SchemeInformation/tsl:NextUpdate/tsl:dateTime[1])'));
        try {
            $date = new DateTimeImmutable($next);
        } catch (Throwable) {
            throw new TrustListRejected('The trusted list has no valid NextUpdate.');
        }
        if ($next === '' || $date <= $at) {
            throw new TrustListRejected('The trusted list has expired or has no NextUpdate.');
        }

        return $date;
    }

    private function sequence(DOMDocument $document): int
    {
        $text = trim((string) self::xpath($document)->evaluate('string(/tsl:TrustServiceStatusList/tsl:SchemeInformation/tsl:TSLSequenceNumber[1])'));
        if (! preg_match('/^[0-9]{1,15}$/', $text)) {
            throw new TrustListRejected('The trusted list has no valid sequence number.');
        }

        return (int) $text;
    }

    private function issueDate(DOMDocument $document): string
    {
        $text = trim((string) self::xpath($document)->evaluate('string(/tsl:TrustServiceStatusList/tsl:SchemeInformation/tsl:ListIssueDateTime[1])'));
        if ($text === '') {
            throw new TrustListRejected('The trusted list has no issue date.');
        }
        try {
            return (new DateTimeImmutable($text))->format(DATE_ATOM);
        } catch (Throwable) {
            throw new TrustListRejected('The trusted list has an invalid issue date.');
        }
    }

    private function assertCountry(DOMDocument $document, string $country): void
    {
        $actual = trim((string) self::xpath($document)->evaluate('string(/tsl:TrustServiceStatusList/tsl:SchemeInformation/tsl:SchemeTerritory[1])'));
        if ($actual !== $country) {
            throw new TrustListRejected('National TSL territory does not match the LOTL pointer.');
        }
    }

    /** @return list<string> */
    private static function fingerprints(DOMXPath $xpath, DOMElement $pointer): array
    {
        $result = [];
        foreach ($xpath->query('./tsl:ServiceDigitalIdentities/tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate', $pointer) ?: [] as $node) {
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

    private static function xpath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('tsl', self::TSL);
        $xpath->registerNamespace('sie', self::SIE);

        return $xpath;
    }
}
