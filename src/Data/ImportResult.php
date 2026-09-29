<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Data;

final readonly class ImportResult
{
    /**
     * @param list<string> $added
     * @param list<string> $removed
     */
    public function __construct(public int $count, public array $added, public array $removed, public bool $dryRun, public bool $retentionRejected = false) {}
}
