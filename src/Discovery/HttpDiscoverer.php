<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\RuntimeException;
use DigitalCz\OpenIDConnect\Http\HttpClient;
use DigitalCz\OpenIDConnect\ProviderMetadata;
use Jose\Component\Core\JWKSet;
use Psr\Http\Client\ClientExceptionInterface;

final class HttpDiscoverer implements Discoverer
{
    public function __construct(private HttpClient $httpClient)
    {
    }

    /**
     * @throws DiscoveryException
     */
    public function discover(string $uri): ProviderMetadata
    {
        $configuration = $this->sendRequest($uri);
        $jwks = $this->sendRequest($configuration['jwks_uri']);

        return new ProviderMetadata($configuration, JWKSet::createFromKeyData($jwks));
    }

    /**
     * @return array<string, mixed>
     */
    private function sendRequest(string $uri): array
    {
        $request = $this->httpClient->createRequest('GET', $uri);

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new DiscoveryException($e->getMessage(), $e->getCode(), $e);
        }

        try {
            return $this->httpClient->parseResponse($response);
        } catch (RuntimeException $e) {
            throw new DiscoveryException('Unable to parse response from ' . $uri, $e->getCode(), $e);
        }
    }
}
