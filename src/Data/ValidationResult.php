<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Data;

final readonly class ValidationResult
{
    public function __construct(public bool $valid, public ?string $reason, public ?Identity $identity = null, public ?ParsedCertificate $certificate = null, public ?string $revocationSource = null, public string $profile = 'default') {}

    public static function reject(string $reason, ?ParsedCertificate $certificate = null, string $profile = 'default'): self
    {
        return new self(false, $reason, null, $certificate, profile: $profile);
    }
}
