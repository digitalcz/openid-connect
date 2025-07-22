<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\Config;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final readonly class ClientCredentials
{
    public function __construct(
        private Config $config,
        private HttpClientInterface $httpClient,
    ) {
    }

    public function fetchTokens(): Tokens
    {
        $issuerMetadata = $this->config->issuerMetadata();
        $clientMetadata = $this->config->clientMetadata();

        $url = $issuerMetadata->tokenEndpoint();
        $options = [
            'body' => [
                'grant_type' => 'client_credentials',
                'scope' => implode(' ', $clientMetadata->defaultScopes()),
            ],
        ];

        $authOptions = $clientMetadata->authenticationMethod()->asOptions($clientMetadata);
        $options = array_merge_recursive($options, $authOptions);

        $response = $this->httpClient->request('POST', $url, $options);

        return Tokens::fromTokenResponse($response->toArray());
    }
}
