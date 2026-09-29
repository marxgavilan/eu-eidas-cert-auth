<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Laravel\Facades;

use Illuminate\Support\Facades\Facade;

/** @method static \Iberfacil\EidasCertAuth\Data\ValidationResult validate(string $raw, ?\DateTimeImmutable $at = null, string $profile = 'default') */
final class EidasCertAuth extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'eidas-cert-auth';
    }
}
