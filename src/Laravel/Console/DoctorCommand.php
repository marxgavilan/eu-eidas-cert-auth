<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Laravel\Console;

use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Config;
use InvalidArgumentException;

final class DoctorCommand extends Command
{
    protected $signature = 'eidas:doctor';

    protected $description = 'Inspect the local eIDAS trust-store configuration without network access.';

    public function handle(): int
    {
        try {
            $this->laravel->make(Options::class);
            $store = $this->laravel->make(TrustStore::class);
        } catch (InvalidArgumentException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }
        $count = count($store->certificates());
        $this->line('Trust store: ' . $store->path);
        $this->line('Qualified CAs: ' . $count);
        $this->line('Region: ' . Config::get('eidas-cert-auth.region', 'ES'));
        $this->line('Certificate server variable: ' . Config::get('eidas-cert-auth.server_variable', 'SSL_CLIENT_CERT'));
        if ($count === 0) {
            $this->error('No trusted CAs are installed. Run eidas:trust-list:update.');

            return self::FAILURE;
        }

        return self::SUCCESS;
    }
}
