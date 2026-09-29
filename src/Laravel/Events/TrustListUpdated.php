<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Laravel\Events;

use Iberfacil\EidasCertAuth\Data\ImportResult;

final readonly class TrustListUpdated
{
    public function __construct(public ImportResult $result) {}
}
