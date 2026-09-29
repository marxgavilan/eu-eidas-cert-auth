<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Laravel\Events;

final readonly class TrustListRejected
{
    public function __construct(public string $reason) {}
}
