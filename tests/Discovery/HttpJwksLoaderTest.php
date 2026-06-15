<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use RuntimeException;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\DecodingExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

#[CoversClass(HttpJwksLoader::class)]
class HttpJwksLoaderTest extends TestCase
{
    public function testLoadThrowsNetworkExceptionOnTransportError(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://example.com/.well-known/jwks.json')
            ->willReturn($response);

        $response->expects($this->once())
            ->method('toArray')
            ->willThrowException($this->createMock(TransportExceptionInterface::class));

        $loader = new HttpJwksLoader($httpClient);

        $this->expectException(NetworkException::class);
        $this->expectExceptionMessage('Failed to fetch JWKS document:');

        $loader->load('https://example.com/.well-known/jwks.json');
    }

    public function testLoadThrowsDiscoveryExceptionOnClientError(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://example.com/.well-known/jwks.json')
            ->willReturn($response);

        $response->expects($this->once())
            ->method('toArray')
            ->willThrowException($this->createMock(ClientExceptionInterface::class));

        $loader = new HttpJwksLoader($httpClient);

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('JWKS endpoint returned error:');

        $loader->load('https://example.com/.well-known/jwks.json');
    }

    public function testLoadThrowsDiscoveryExceptionOnServerError(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://example.com/.well-known/jwks.json')
            ->willReturn($response);

        $response->expects($this->once())
            ->method('toArray')
            ->willThrowException($this->createMock(ServerExceptionInterface::class));

        $loader = new HttpJwksLoader($httpClient);

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('JWKS endpoint returned error:');

        $loader->load('https://example.com/.well-known/jwks.json');
    }

    public function testLoadThrowsDiscoveryExceptionOnDecodingError(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://example.com/.well-known/jwks.json')
            ->willReturn($response);

        $response->expects($this->once())
            ->method('toArray')
            ->willThrowException($this->createMock(DecodingExceptionInterface::class));

        $loader = new HttpJwksLoader($httpClient);

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('Failed to decode JWKS document:');

        $loader->load('https://example.com/.well-known/jwks.json');
    }

    public function testLoadThrowsDiscoveryExceptionOnUnexpectedError(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://example.com/.well-known/jwks.json')
            ->willReturn($response);

        $response->expects($this->once())
            ->method('toArray')
            ->willThrowException(new RuntimeException('Unexpected error'));

        $loader = new HttpJwksLoader($httpClient);

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('Unexpected error during JWKS loading:');

        $loader->load('https://example.com/.well-known/jwks.json');
    }
}
