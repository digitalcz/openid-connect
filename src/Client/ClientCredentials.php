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
}
