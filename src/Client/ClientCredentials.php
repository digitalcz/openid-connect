<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\Config;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * OAuth2 Client Credentials flow for machine-to-machine authentication.
 */
final readonly class ClientCredentials
{
    use RefreshTokenTrait;

    /**
     * @param Config $config OIDC configuration
     * @param HttpClientInterface $httpClient HTTP client for requests
     */
    public function __construct(
        private Config $config,
        private HttpClientInterface $httpClient,
    ) {
    }

    /**
     * Obtain access token using client credentials.
     *
     * @return Tokens Access token for API access
     */
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

    /**
     * Refresh access tokens using refresh token.
     *
     * @param Tokens $tokens Current tokens with refresh token
     * @return Tokens New tokens with fresh access token
     */
    public function refreshToken(Tokens $tokens): Tokens
    {
        return $this->doRefreshToken($tokens);
    }
}
