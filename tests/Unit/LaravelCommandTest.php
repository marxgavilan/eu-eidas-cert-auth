<?php

declare(strict_types=1);

namespace Iberfacil\EidasCertAuth\Tests\Unit;

use Iberfacil\EidasCertAuth\Laravel\Console\DoctorCommand;
use Iberfacil\EidasCertAuth\Laravel\Console\TrustListUpdateCommand;
use Iberfacil\EidasCertAuth\Laravel\Events\TrustListUpdated;
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Tests\Support\SignedLists;
use Iberfacil\EidasCertAuth\Tests\Support\TestPki;
use Iberfacil\EidasCertAuth\Transport\FakeTransport;
use Iberfacil\EidasCertAuth\Trust\TrustListImporter;
use Iberfacil\EidasCertAuth\Trust\TrustStore;
use Iberfacil\EidasCertAuth\Trust\XmlSignatureVerifier;
use Illuminate\Console\Command;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

final class LaravelCommandTest extends TestCase
{
    public function testUpdateCommandDryRunAndPublicationDispatch(): void
    {
        $pki = new TestPki();
        $lotlSigner = $pki->issue(['CN' => 'LOTL']);
        $nationalSigner = $pki->issue(['CN' => 'National']);
        $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
        $url = 'https://lists.example.test/es.xml';
        $lotl = SignedLists::sign(SignedLists::lotl('ES', $url, $nationalSigner['pem']), $lotlSigner);
        $transport = (new FakeTransport())->respond(Options::LOTL_URL, $lotl)->respond($url, SignedLists::sign(SignedLists::tsl('ES', [$ca['pem']]), $nationalSigner));
        $dir = sys_get_temp_dir() . '/eidas-artisan-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        $store = new TrustStore($dir . '/trust');
        $options = new Options(lotlSignerFingerprints: [hash('sha256', TestPki::der($lotlSigner['pem']))]);
        $importer = new TrustListImporter($transport, new XmlSignatureVerifier(), $store, $options);
        $events = $this->createMock(Dispatcher::class);
        $events->expects(self::once())->method('dispatch')->with(self::isInstanceOf(TrustListUpdated::class));
        $command = new TrustListUpdateCommand();
        try {
            $this->setIo($command, ['--dry-run' => true]);
            self::assertSame(0, $command->handle($importer, $events));
            self::assertFalse(is_link($store->path));
            $this->setIo($command);
            self::assertSame(0, $command->handle($importer, $events));
            self::assertCount(1, $store->certificates());
        } finally {
            foreach (glob($dir . '/.trust.*') ?: [] as $generation) {
                if (is_dir($generation)) {
                    foreach (glob($generation . '/*') ?: [] as $file) {
                        unlink($file);
                    }
                    rmdir($generation);
                } else {
                    unlink($generation);
                }
            }
            if (is_link($store->path)) {
                unlink($store->path);
            }
            rmdir($dir);
        }
    }

    public function testDoctorCommandReportsEmptyAndPopulatedStore(): void
    {
        $dir = sys_get_temp_dir() . '/eidas-doctor-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        $store = new TrustStore($dir . '/trust');
        $config = new class {
            public function get(string $key, mixed $default = null): mixed
            {
                return $default;
            }
        };
        $app = $this->createMockForIntersectionOfInterfaces([Application::class, \ArrayAccess::class]);
        self::assertInstanceOf(Application::class, $app);
        $app->method('offsetGet')->with('config')->willReturn($config);
        $app->method('make')->willReturnCallback(static fn(string $abstract): mixed => $abstract === Options::class ? new Options() : $store);
        Facade::setFacadeApplication($app);
        $command = new DoctorCommand();
        $command->setLaravel($app);
        try {
            $this->setIo($command);
            self::assertSame(1, $command->handle());
            $pki = new TestPki();
            $ca = $pki->issue(['CN' => 'CA'], profile: 'ca');
            $store->publish([hash('sha256', TestPki::der($ca['pem'])) => ['pem' => $ca['pem'], 'country' => 'ES', 'service' => 'CA/QC']]);
            self::assertSame(0, $command->handle());
        } finally {
            Facade::clearResolvedInstances();
            Facade::setFacadeApplication(null);
            foreach (glob($dir . '/.trust.*') ?: [] as $generation) {
                if (is_dir($generation)) {
                    foreach (glob($generation . '/*') ?: [] as $file) {
                        unlink($file);
                    }
                    rmdir($generation);
                } else {
                    unlink($generation);
                }
            }
            if (is_link($store->path)) {
                unlink($store->path);
            }
            rmdir($dir);
        }
    }

    public function testDoctorCommandReportsInvalidOptions(): void
    {
        $app = $this->createMock(Application::class);
        $app->method('make')->willReturnCallback(static fn(string $abstract): mixed => $abstract === Options::class ? new Options(region: 'invalid') : null);
        $command = new DoctorCommand();
        $command->setLaravel($app);
        $this->setIo($command);

        self::assertSame(Command::FAILURE, $command->handle());
    }

    public function testDoctorCommandPropagatesUnexpectedFailures(): void
    {
        $app = $this->createMock(Application::class);
        $app->method('make')->willThrowException(new RuntimeException('Container failed.'));
        $command = new DoctorCommand();
        $command->setLaravel($app);
        $this->setIo($command);

        $this->expectException(RuntimeException::class);
        $command->handle();
    }

    /** @param array<string, bool> $options */
    private function setIo(Command $command, array $options = []): void
    {
        $input = new ArrayInput($options, $command->getDefinition());
        (new \ReflectionProperty($command, 'input'))->setValue($command, $input);
        (new \ReflectionProperty($command, 'output'))->setValue($command, new BufferedOutput());
    }
}
