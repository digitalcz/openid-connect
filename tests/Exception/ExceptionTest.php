<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

use DigitalCz\OpenIDConnect\TestCase;
use Exception;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Throwable;

#[CoversClass(ConfigurationException::class)]
#[CoversClass(DiscoveryException::class)]
#[CoversClass(NetworkException::class)]
#[CoversClass(IntrospectionException::class)]
class ExceptionTest extends TestCase
{
    public function testConfigurationExceptionImplementsInterface(): void
    {
        $exception = new ConfigurationException('test message');

        $this->assertInstanceOf(Throwable::class, $exception);
        $this->assertInstanceOf(LogicException::class, $exception);
        $this->assertSame('test message', $exception->getMessage());
    }

    public function testDiscoveryExceptionImplementsInterface(): void
    {
        $exception = new DiscoveryException('test message');

        $this->assertInstanceOf(Throwable::class, $exception);
        $this->assertInstanceOf(RuntimeException::class, $exception);
        $this->assertSame('test message', $exception->getMessage());
    }

    public function testNetworkExceptionImplementsInterface(): void
    {
        $exception = new NetworkException('test message');

        $this->assertInstanceOf(Throwable::class, $exception);
        $this->assertInstanceOf(RuntimeException::class, $exception);
        $this->assertSame('test message', $exception->getMessage());
    }

    public function testIntrospectionExceptionImplementsInterface(): void
    {
        $exception = new IntrospectionException('test message');

        $this->assertInstanceOf(Throwable::class, $exception);
        $this->assertInstanceOf(RuntimeException::class, $exception);
        $this->assertSame('test message', $exception->getMessage());
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public static function exceptionWithChainProvider(): array
    {
        return [
            'ConfigurationException' => [ConfigurationException::class],
            'DiscoveryException' => [DiscoveryException::class],
            'NetworkException' => [NetworkException::class],
            'IntrospectionException' => [IntrospectionException::class],
        ];
    }

    /**
     * @param class-string<Throwable> $exceptionClass
     */
    #[DataProvider('exceptionWithChainProvider')]
    public function testExceptionChaining(string $exceptionClass): void
    {
        $previous = new Exception('previous exception');
        $exception = new $exceptionClass('test message', 123, $previous);

        $this->assertSame('test message', $exception->getMessage());
        $this->assertSame(123, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
