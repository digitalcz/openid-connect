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

#[CoversClass(HttpDiscoverer::class)]
class HttpDiscovererTest extends TestCase
{
    public function testDiscoverThrowsNetworkExceptionOnTransportError(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://example.com/.well-known/openid-configuration')
            ->willReturn($response);

        $response->expects($this->once())
            ->method('toArray')
            ->willThrowException($this->createMock(TransportExceptionInterface::class));

        $discoverer = new HttpDiscoverer($httpClient);

        $this->expectException(NetworkException::class);
        $this->expectExceptionMessage('Failed to fetch OIDC discovery document:');

        $discoverer->discover('https://example.com');
    }

    public function testDiscoverThrowsDiscoveryExceptionOnClientError(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://example.com/.well-known/openid-configuration')
            ->willReturn($response);

        $response->expects($this->once())
            ->method('toArray')
            ->willThrowException($this->createMock(ClientExceptionInterface::class));

        $discoverer = new HttpDiscoverer($httpClient);

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('OIDC discovery endpoint returned error:');

        $discoverer->discover('https://example.com');
    }

    public function testDiscoverThrowsDiscoveryExceptionOnServerError(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://example.com/.well-known/openid-configuration')
            ->willReturn($response);

        $response->expects($this->once())
            ->method('toArray')
            ->willThrowException($this->createMock(ServerExceptionInterface::class));

        $discoverer = new HttpDiscoverer($httpClient);

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('OIDC discovery endpoint returned error:');

        $discoverer->discover('https://example.com');
    }

    public function testDiscoverThrowsDiscoveryExceptionOnDecodingError(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://example.com/.well-known/openid-configuration')
            ->willReturn($response);

        $response->expects($this->once())
            ->method('toArray')
            ->willThrowException($this->createMock(DecodingExceptionInterface::class));

        $discoverer = new HttpDiscoverer($httpClient);

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('Failed to decode OIDC discovery document:');

        $discoverer->discover('https://example.com');
    }

    public function testDiscoverThrowsDiscoveryExceptionOnUnexpectedError(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://example.com/.well-known/openid-configuration')
            ->willReturn($response);

        $response->expects($this->once())
            ->method('toArray')
            ->willThrowException(new RuntimeException('Unexpected error'));

        $discoverer = new HttpDiscoverer($httpClient);

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('Unexpected error during OIDC discovery:');

        $discoverer->discover('https://example.com');
    }
}
