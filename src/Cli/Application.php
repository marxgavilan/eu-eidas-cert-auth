<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Cli;

use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Transport\CurlTransport;
use Iberfacil\EidasCertAuth\Trust\TrustListImporter;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use Iberfacil\EidasCertAuth\Trust\XmlSignatureVerifier;
use Throwable;

final class Application
{
    /** @param list<string> $arguments */
    public function run(array $arguments): int
    {
        $command = $arguments[1] ?? 'help';
        if ($command === 'help') {
            echo "Usage: eidas-cert-auth <doctor|trust-list:update> --store=/path/to/live-store [--region=ES] [--force] [--dry-run]\n";

            return 0;
        }
        $flags = array_slice($arguments, 2);
        $storePath = $this->value($flags, '--store=') ?? (getenv('EIDAS_STORE_PATH') ?: null);
        if (! is_string($storePath) || $storePath === '') {
            fwrite(STDERR, "Set --store=/path/to/live-store or EIDAS_STORE_PATH.\n");

            return 1;
        }
        $region = $this->value($flags, '--region=') ?? (getenv('EIDAS_REGION') ?: 'ES');
        try {
            $options = new Options(region: $region);
            $store = new TrustStore($storePath, $options->minimumRetentionPercent);
            if ($command === 'doctor') {
                $count = count($store->certificates());
                echo "Region: {$region}\nQualified CAs: {$count}\nStore: {$storePath}\n";

                return $count > 0 ? 0 : 1;
            }
            if ($command === 'trust-list:update') {
                $importer = new TrustListImporter(new CurlTransport(), new XmlSignatureVerifier(), $store, $options);
                $result = $importer->importLotl(force: in_array('--force', $flags, true), dryRun: in_array('--dry-run', $flags, true));
                echo ($result->dryRun ? 'Dry run: ' : '') . $result->count . " qualified CAs\n";
                foreach ($result->added as $fingerprint) {
                    echo '+ ' . $fingerprint . "\n";
                }
                foreach ($result->removed as $fingerprint) {
                    echo '- ' . $fingerprint . "\n";
                }

                if ($result->retentionRejected) {
                    fwrite(STDERR, "The CA retention safeguard would reject this update.\n");

                    return 1;
                }

                return 0;
            }
        } catch (Throwable $exception) {
            fwrite(STDERR, $exception->getMessage() . "\n");

            return 1;
        }
        echo "Usage: eidas-cert-auth <doctor|trust-list:update> --store=/path/to/live-store [--region=ES] [--force] [--dry-run]\n";

        return 1;
    }

    /** @param list<string> $flags */
    private function value(array $flags, string $prefix): ?string
    {
        foreach ($flags as $flag) {
            if (str_starts_with($flag, $prefix)) {
                return substr($flag, strlen($prefix));
            }
        }

        return null;
    }
}
