<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Data;

use DateTimeImmutable;

final readonly class ParsedCertificate
{
    /**
     * @param array<string, mixed> $subject
     * @param array<string, mixed> $issuer
     * @param list<string> $ocspUrls
     * @param list<string> $crlUrls
     * @param list<string> $caIssuerUrls
     */
    public function __construct(
        public string $pem,
        public string $fingerprint,
        public array $subject,
        public array $issuer,
        public DateTimeImmutable $notBefore,
        public DateTimeImmutable $notAfter,
        public ?string $keyUsage,
        public ?string $extendedKeyUsage,
        public bool $qualified,
        public array $ocspUrls,
        public array $crlUrls,
        public array $caIssuerUrls = [],
    ) {}
}
