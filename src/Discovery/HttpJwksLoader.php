<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\DecodingExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * HTTP JWKS loader.
 */
final readonly class HttpJwksLoader implements JwksLoader
{
    public function __construct(
        private HttpClientInterface $httpClient,
    ) {
    }

    /**
     * @return mixed[]
     *
     * @throws DiscoveryException
     * @throws NetworkException
     */
    public function load(string $jwksUri): array
    {
        try {
            return $this->httpClient->request('GET', $jwksUri)->toArray();
        } catch (TransportExceptionInterface $e) {
            throw new NetworkException('Failed to fetch JWKS document: ' . $e->getMessage(), 0, $e);
        } catch (ClientExceptionInterface | ServerExceptionInterface | RedirectionExceptionInterface $e) {
            throw new DiscoveryException('JWKS endpoint returned error: ' . $e->getMessage(), 0, $e);
        } catch (DecodingExceptionInterface $e) {
            throw new DiscoveryException('Failed to decode JWKS document: ' . $e->getMessage(), 0, $e);
        } catch (Throwable $e) {
            throw new DiscoveryException('Unexpected error during JWKS loading: ' . $e->getMessage(), 0, $e);
        }
    }
}
