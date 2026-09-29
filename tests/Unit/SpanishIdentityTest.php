<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use Iberfacil\EidasCertAuth\Certificate\CertificateParser;
use Iberfacil\EidasCertAuth\Data\ParsedCertificate;
use Iberfacil\EidasCertAuth\Identity\SpanishIdentityExtractor;
use Iberfacil\EidasCertAuth\Tests\Support\TestPki;
use PHPUnit\Framework\TestCase;

final class SpanishIdentityTest extends TestCase
{
    public function testCommonNameFallbackRequiresValidDniLetter(): void
    {
        $pki = new TestPki();
        $parser = new CertificateParser();
        $extractor = new SpanishIdentityExtractor();
        $valid = $parser->parse($pki->issue(['CN' => 'Citizen 00000000T', 'C' => 'ES'], profile: 'client')['pem']);
        $invalid = $parser->parse($pki->issue(['CN' => 'Seal 00000000Z', 'C' => 'ES'], profile: 'client')['pem']);
        self::assertInstanceOf(ParsedCertificate::class, $valid);
        self::assertInstanceOf(ParsedCertificate::class, $invalid);
        self::assertSame('00000000T', $extractor->extract($valid)->identifier);
        self::assertNull($extractor->extract($invalid)->identifier);
    }

    public function testBareSerialRequiresValidDniOrNieLetter(): void
    {
        $pki = new TestPki();
        $parser = new CertificateParser();
        $extractor = new SpanishIdentityExtractor();
        foreach (['12345678Z' => '12345678Z', 'X0000000T' => 'X0000000T', '12345678A' => null, 'X0000000A' => null] as $serial => $expected) {
            $certificate = $parser->parse($pki->issue(['CN' => 'Citizen 00000000T', 'serialNumber' => $serial, 'C' => 'ES'], profile: 'client')['pem']);
            self::assertInstanceOf(ParsedCertificate::class, $certificate);
            self::assertSame($expected, $extractor->extract($certificate)->identifier);
        }
    }
}
