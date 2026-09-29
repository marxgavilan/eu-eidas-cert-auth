<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Identity;

final class ItalianIdentityExtractor extends GenericIdentityExtractor
{
    public function supports(string $country): bool
    {
        return $country === 'IT';
    }
}
