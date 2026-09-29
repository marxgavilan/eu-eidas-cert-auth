<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use Iberfacil\EidasCertAuth\Certificate\QualificationCriteria;
use Iberfacil\EidasCertAuth\Tests\Support\TestPki;
use PHPUnit\Framework\TestCase;

final class QualificationCriteriaTest extends TestCase
{
    public function testNestedAndNoneCriteriaApplyOnlyToMatchingCertificates(): void
    {
        $pem = (new TestPki())->issue(['CN' => 'Citizen'], profile: 'client')['pem'];
        $wrap = static fn(string $criteria): string => '<root xmlns:sie="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#">' . $criteria . '</root>';
        $digitalSignature = '<sie:KeyUsage><sie:KeyUsageBit name="digitalSignature">true</sie:KeyUsageBit></sie:KeyUsage>';
        $keyEncipherment = '<sie:KeyUsage><sie:KeyUsageBit name="keyEncipherment">true</sie:KeyUsageBit></sie:KeyUsage>';
        self::assertTrue(QualificationCriteria::excludes($pem, [$wrap('<sie:CriteriaList assert="atLeastOne"><sie:CriteriaList assert="all">' . $digitalSignature . '</sie:CriteriaList>' . $keyEncipherment . '</sie:CriteriaList>')]));
        self::assertFalse(QualificationCriteria::excludes($pem, [$wrap('<sie:CriteriaList assert="none">' . $digitalSignature . '</sie:CriteriaList>')]));
        self::assertTrue(QualificationCriteria::excludes($pem, [$wrap('<sie:CriteriaList assert="none">' . $keyEncipherment . '</sie:CriteriaList>')]));
        self::assertTrue(QualificationCriteria::excludes($pem, [$wrap('<sie:CriteriaList assert="none"><sie:otherCriteriaList/></sie:CriteriaList>')]));
    }
}
