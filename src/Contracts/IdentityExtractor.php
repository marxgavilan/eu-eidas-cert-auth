<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Contracts;

use Iberfacil\EidasCertAuth\Data\Identity;
use Iberfacil\EidasCertAuth\Data\ParsedCertificate;

interface IdentityExtractor
{
    public function supports(string $country): bool;

    public function extract(ParsedCertificate $certificate): Identity;
}
