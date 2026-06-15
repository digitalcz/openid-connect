<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\HttpClient\ResponseStreamInterface;

#[CoversClass(SecureHttpClient::class)]
class SecureHttpClientTest extends TestCase
{
    public function testRequestRejectsInsecureRemoteUrlWithoutDelegating(): void
    {
        $inner = $this->createMock(HttpClientInterface::class);
        $inner->expects($this->never())->method('request');

        $client = new SecureHttpClient($inner);

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('HTTPS is required');

        $client->request('POST', 'http://idp.example.com/token');
    }

    public function testRequestAllowsHttpsAndDelegates(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $inner = $this->createMock(HttpClientInterface::class);
        $inner->expects($this->once())
            ->method('request')
            ->with('GET', 'https://idp.example.com/userinfo', ['auth_bearer' => 'tok'])
            ->willReturn($response);

        $client = new SecureHttpClient($inner);

        $this->assertSame(
            $response,
            $client->request('GET', 'https://idp.example.com/userinfo', ['auth_bearer' => 'tok']),
        );
    }

    public function testRequestAllowsHttpLoopbackAndDelegates(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $inner = $this->createMock(HttpClientInterface::class);
        $inner->expects($this->once())
            ->method('request')
            ->with('GET', 'http://127.0.0.1/.well-known/jwks.json')
            ->willReturn($response);

        $client = new SecureHttpClient($inner);

        $this->assertSame($response, $client->request('GET', 'http://127.0.0.1/.well-known/jwks.json'));
    }

    public function testStreamDelegates(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $stream = $this->createMock(ResponseStreamInterface::class);
        $inner = $this->createMock(HttpClientInterface::class);
        $inner->expects($this->once())
            ->method('stream')
            ->with($response, 1.5)
            ->willReturn($stream);

        $client = new SecureHttpClient($inner);

        $this->assertSame($stream, $client->stream($response, 1.5));
    }

    public function testWithOptionsReturnsSecureClient(): void
    {
        $reconfiguredInner = $this->createMock(HttpClientInterface::class);
        $inner = $this->createMock(HttpClientInterface::class);
        $inner->expects($this->once())
            ->method('withOptions')
            ->with(['base_uri' => 'https://idp.example.com'])
            ->willReturn($reconfiguredInner);

        $client = new SecureHttpClient($inner);
        $reconfigured = $client->withOptions(['base_uri' => 'https://idp.example.com']);

        $this->assertInstanceOf(SecureHttpClient::class, $reconfigured);
        $this->assertNotSame($client, $reconfigured);
    }
}
