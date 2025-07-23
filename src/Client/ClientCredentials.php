<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\Config;
use InvalidArgumentException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * OAuth2 Client Credentials flow for machine-to-machine authentication.
 */
final readonly class ClientCredentials
{
    use RequestTokensTrait;

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
     * @param array<string, string> $params Additional body parameters
     * @return Tokens Access token for API access
     */
    public function fetchTokens(array $params = []): Tokens
    {
        $clientMetadata = $this->config->clientMetadata();

        $params['grant_type'] ??= 'client_credentials';
        $params['scope'] ??= implode(' ', $clientMetadata->defaultScopes());

        return $this->requestTokens($params);
    }

    /**
     * Refresh access tokens using refresh token.
     *
     * @param Tokens $tokens Current tokens with refresh token
     * @param array<string, string> $params Additional body parameters
     * @return Tokens New tokens with fresh access token
     */
    public function refreshToken(Tokens $tokens, array $params = []): Tokens
    {
        if ($tokens->refreshToken() === null) {
            throw new InvalidArgumentException('Cannot refresh tokens without a refresh token.');
        }

        $params['grant_type'] ??= 'refresh_token';
        $params['refresh_token'] ??= (string)$tokens->refreshToken();

        $newTokens = $this->requestTokens($params);

        return new Tokens(
            accessToken: $newTokens->accessToken(),
            refreshToken: $newTokens->refreshToken() ?? $tokens->refreshToken(),
            idToken: $newTokens->idToken() ?? $tokens->idToken(),
            scope: $newTokens->scope(),
            tokenType: $newTokens->tokenType(),
            expiresIn: $newTokens->expiresIn(),
        );
    }
}
