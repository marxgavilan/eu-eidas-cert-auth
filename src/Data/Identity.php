<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Data;

final readonly class Identity
{
    public function __construct(
        public ?string $givenName,
        public ?string $surnames,
        public ?string $identifier,
        public string $country,
        public string $personType,
        public ?string $organization,
        public ?string $organizationIdentifier,
        public ?string $representation,
        public ?string $identifierScheme,
    ) {}
}
