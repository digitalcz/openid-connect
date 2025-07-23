<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

trait RequestTokensTrait
{
    /**
     * Execute token request with common logic.
     *
     * @param array<string, string|null> $params Request body parameters
     * @return Tokens Created tokens
     */
    private function requestTokens(array $params): Tokens
    {
        $issuerMetadata = $this->config->issuerMetadata();
        $clientMetadata = $this->config->clientMetadata();

        $url = $issuerMetadata->tokenEndpoint();
        $options = ['body' => array_filter($params)];
        $options = $clientMetadata->applyCredentials($options);

        $response = $this->httpClient->request('POST', $url, $options);

        return Tokens::fromTokenResponse($response->toArray());
    }
}
