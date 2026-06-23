<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;

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

        $response = $this->httpClient->request('POST', $url, $options);

        return Tokens::fromTokenResponse($response->toArray());
    }
}
