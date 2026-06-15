<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(SecureUrl::class)]
class SecureUrlTest extends TestCase
{
    #[DataProvider('secureUrlProvider')]
    public function testRequireSecureAllowsSecureUrls(string $url): void
    {
        $this->expectNotToPerformAssertions();

        SecureUrl::requireSecure($url);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function secureUrlProvider(): array
    {
        return [
            'https remote' => ['https://auth.example.com/.well-known/openid-configuration'],
            'uppercase https scheme' => ['HTTPS://auth.example.com/.well-known/openid-configuration'],
            'mixed-case http loopback scheme' => ['HttP://localhost/.well-known/jwks.json'],
            'http localhost' => ['http://localhost/.well-known/jwks.json'],
            'http 127.0.0.1' => ['http://127.0.0.1:8080/jwks'],
            'http ipv6 loopback' => ['http://[::1]/jwks'],
        ];
    }

    #[DataProvider('insecureUrlProvider')]
    public function testRequireSecureRejectsInsecureUrls(string $url): void
    {
        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('HTTPS is required');

        SecureUrl::requireSecure($url);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function insecureUrlProvider(): array
    {
        return [
            'http remote' => ['http://auth.example.com/.well-known/openid-configuration'],
            'http remote ip' => ['http://10.0.0.5/jwks'],
            'file scheme' => ['file:///etc/passwd'],
            'no scheme' => ['auth.example.com/jwks'],
        ];
    }
}
