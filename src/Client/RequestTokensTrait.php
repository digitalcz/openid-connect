<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientExceptionInterface;

trait RequestTokensTrait
{
    /**
     * Execute token request with common logic.
     *
     * @param array<string, string|null> $params Request body parameters
     * @return Tokens Created tokens
     *
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the token endpoint cannot be reached
     */
    private function requestTokens(array $params): Tokens
    {
        $issuerMetadata = $this->config->issuerMetadata();
        $clientMetadata = $this->config->clientMetadata();

        $url = $issuerMetadata->tokenEndpoint();
        $options = ['body' => array_filter($params)];

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $options = $authenticator->applyAuthentication($options);

        try {
            $data = $this->httpClient->request('POST', $url, $options)->toArray();
        } catch (HttpClientExceptionInterface $e) {
            throw new NetworkException('Token request failed: ' . $e->getMessage(), 0, $e);
        }

        return Tokens::fromTokenResponse($data);
    }
}
