<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\Config;
use InvalidArgumentException;
use RuntimeException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * OAuth2 Authorization Code flow implementation for web applications.
 */
final readonly class AuthorizationCode
{
    use RefreshTokenTrait;

    /**
     * @param Config $config OIDC configuration
     * @param HttpClientInterface $httpClient HTTP client for requests
     * @param IdTokenValidator $validator ID token validator
     */
    public function __construct(
        private Config $config,
        private HttpClientInterface $httpClient,
        private IdTokenValidator $validator,
    ) {
    }

    /**
     * Create authorization URL for user redirect.
     *
     * @param array<string, string> $params Additional query parameters
     * @return string Authorization URL
     */
    public function createAuthorizationUrl(array $params = []): string
    {
        $issuerMetadata = $this->config->issuerMetadata();
        $clientMetadata = $this->config->clientMetadata();

        $authorizationEndpoint = $issuerMetadata->authorizationEndpoint();

        $params['client_id'] ??= $clientMetadata->clientId();
        $params['response_type'] ??= 'code';
        $params['scope'] ??= implode(' ', $clientMetadata->defaultScopes());

        if ($clientMetadata->redirectUri() !== null) {
            $params['redirect_uri'] ??= $clientMetadata->redirectUri();
        }

        return $authorizationEndpoint . '?' . http_build_query($params);
    }

    /**
     * Exchange authorization code for tokens.
     *
     * @param string $code Authorization code from callback
     * @param string|null $nonce Nonce for ID token validation
     * @return Tokens Access token, refresh token, and ID token
     */
    public function fetchTokens(string $code, ?string $nonce = null): Tokens
    {
        $issuerMetadata = $this->config->issuerMetadata();
        $clientMetadata = $this->config->clientMetadata();

        $url = $issuerMetadata->tokenEndpoint();
        $options = [
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $clientMetadata->redirectUri(),
            ],
        ];

        $authOptions = $clientMetadata->authenticationMethod()->asOptions($clientMetadata);
        $options = array_merge_recursive($options, $authOptions);

        $response = $this->httpClient->request('POST', $url, $options);

        $tokens = Tokens::fromTokenResponse($response->toArray());

        if ($tokens->idToken() !== null) {
            $this->validator->validate($tokens->idToken(), $nonce);
        }

        return $tokens;
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

    /**
     * Fetch user information from userinfo endpoint.
     *
     * @param Tokens $tokens Tokens with access token
     * @return Userinfo User profile information
     */
    public function fetchUserinfo(Tokens $tokens): Userinfo
    {
        $issuerMetadata = $this->config->issuerMetadata();
        $userinfoEndpoint = $issuerMetadata->userinfoEndpoint();
        $accessToken = $tokens->accessToken();

        if ($accessToken === null) {
            throw new InvalidArgumentException('Cannot fetch userinfo without an access token.');
        }

        /** @var array<string, mixed> $response */
        $response = $this->httpClient->request('GET', $userinfoEndpoint, ['auth_bearer' => $accessToken])->toArray();

        $userinfo = new Userinfo($response);

        if ($tokens->idToken() !== null && $tokens->idToken()->sub() !== $userinfo->sub()) {
            throw new RuntimeException('Userinfo sub does not match id_token sub.');
        }

        return $userinfo;
    }
}
