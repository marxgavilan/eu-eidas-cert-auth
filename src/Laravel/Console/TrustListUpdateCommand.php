<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Laravel\Console;

use Iberfacil\EidasCertAuth\Laravel\Events\TrustListRejected as TrustListRejectedEvent;
use Iberfacil\EidasCertAuth\Laravel\Events\TrustListUpdated;
use Iberfacil\EidasCertAuth\Trust\TrustListImporter;
use Illuminate\Console\Command;
use Illuminate\Contracts\Events\Dispatcher;
use Throwable;

final class TrustListUpdateCommand extends Command
{
    protected $signature = 'eidas:trust-list:update {--force} {--dry-run}';

    protected $description = 'Verify the EU LOTL and national TSLs, then atomically update qualified CAs.';

    public function handle(TrustListImporter $importer, Dispatcher $events): int
    {
        try {
            $result = $importer->importLotl(force: (bool) $this->option('force'), dryRun: (bool) $this->option('dry-run'));
        } catch (Throwable $exception) {
            $events->dispatch(new TrustListRejectedEvent($exception->getMessage()));
            $this->error($exception->getMessage());

            return self::FAILURE;
        }
        $this->info(($result->dryRun ? 'Dry run: ' : '') . $result->count . ' trusted CAs; ' . count($result->added) . ' added, ' . count($result->removed) . ' removed.');
        foreach ($result->added as $fingerprint) {
            $this->line('+ ' . $fingerprint);
        }
        foreach ($result->removed as $fingerprint) {
            $this->line('- ' . $fingerprint);
        }
        if ($result->retentionRejected) {
            $this->error('The CA retention safeguard would reject this update.');

            return self::FAILURE;
        }
        if (! $result->dryRun) {
            $events->dispatch(new TrustListUpdated($result));
        }

        return self::SUCCESS;
    }
}
