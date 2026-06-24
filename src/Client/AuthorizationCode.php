<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;
use DigitalCz\OpenIDConnect\Util\Pkce;
use InvalidArgumentException;
use RuntimeException;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * OAuth2 Authorization Code flow implementation for web applications.
 */
final readonly class AuthorizationCode
{
    use RequestTokensTrait;

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
     * @return AuthorizationUrlResult Authorization URL with security parameters
     *
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the discovery endpoint cannot be reached
     */
    public function createAuthorizationUrl(array $params = []): AuthorizationUrlResult
    {
        $issuerMetadata = $this->config->issuerMetadata();
        $clientMetadata = $this->config->clientMetadata();

        $authorizationEndpoint = $issuerMetadata->authorizationEndpoint();

        $params['client_id'] ??= $clientMetadata->clientId();
        $params['response_type'] ??= 'code';
        $params['scope'] ??= implode(' ', $clientMetadata->defaultScopes());
        $params['state'] ??= bin2hex(random_bytes(16));

        if (str_contains($params['scope'], 'openid')) {
            $params['nonce'] ??= bin2hex(random_bytes(16));
        }

        if ($clientMetadata->redirectUri() !== null) {
            $params['redirect_uri'] ??= $clientMetadata->redirectUri();
        }

        if ($clientMetadata->pkceMethod() !== null) {
            $pkcePair = Pkce::generatePair($clientMetadata->pkceMethod());

            $params['code_challenge'] = $pkcePair['challenge'];
            $params['code_challenge_method'] = $pkcePair['method'];
            $codeVerifier = $pkcePair['verifier'];
        }

        $url = $authorizationEndpoint . '?' . http_build_query($params);

        return new AuthorizationUrlResult(
            url: $url,
            state: $params['state'],
            nonce: $params['nonce'] ?? null,
            codeVerifier: $codeVerifier ?? null,
        );
    }

    /**
     * Create logout URL for user session termination.
     *
     * @param array<string, string> $params Additional query parameters
     * @return string Logout URL with query parameters
     *
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the discovery endpoint cannot be reached
     */
    public function createLogoutUrl(array $params = []): string
    {
        $issuerMetadata = $this->config->issuerMetadata();
        $clientMetadata = $this->config->clientMetadata();

        $endSessionEndpoint = $issuerMetadata->endSessionEndpoint();

        $params['client_id'] ??= $clientMetadata->clientId();

        return $endSessionEndpoint . '?' . http_build_query($params);
    }

    /**
     * Exchange authorization code for tokens.
     *
     * @param string $code Authorization code from callback
     * @param string|null $nonce Nonce for ID token validation
     * @param string|null $codeVerifier PKCE code verifier (required if PKCE was used)
     * @param array<string, string> $params Additional body parameters
     * @return Tokens Access token, refresh token, and ID token
     *
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws InvalidTokenException if the returned ID token fails validation
     * @throws NetworkException if the token endpoint cannot be reached
     */
    public function fetchTokens(
        string $code,
        ?string $nonce = null,
        ?string $codeVerifier = null,
        array $params = [],
    ): Tokens {
        $clientMetadata = $this->config->clientMetadata();

        $params['grant_type'] ??= 'authorization_code';
        $params['code'] ??= $code;
        $params['redirect_uri'] ??= $clientMetadata->redirectUri();

        if ($codeVerifier !== null) {
            $params['code_verifier'] ??= $codeVerifier;
        }

        $tokens = $this->requestTokens($params);

        if ($tokens->idToken() !== null) {
            $this->validator->validate($tokens->idToken(), $nonce);
        }

        return $tokens;
    }

    /**
     * Refresh access tokens using refresh token.
     *
     * @param Tokens $tokens Current tokens with refresh token
     * @param array<string, string> $params Additional body parameters
     * @return Tokens New tokens with fresh access token
     *
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the token endpoint cannot be reached
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

    /**
     * Fetch user information from userinfo endpoint.
     *
     * @param Tokens $tokens Tokens with access token
     * @return Userinfo User profile information
     *
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the userinfo endpoint cannot be reached
     */
    public function fetchUserinfo(Tokens $tokens): Userinfo
    {
        $issuerMetadata = $this->config->issuerMetadata();
        $userinfoEndpoint = $issuerMetadata->userinfoEndpoint();
        $accessToken = $tokens->accessToken();

        if ($accessToken === null) {
            throw new InvalidArgumentException('Cannot fetch userinfo without an access token.');
        }

        $options = ['auth_bearer' => (string)$accessToken];

        try {
            /** @var array<string, mixed> $response */
            $response = $this->httpClient->request('GET', $userinfoEndpoint, $options)->toArray();
        } catch (HttpClientExceptionInterface $e) {
            throw new NetworkException('Userinfo request failed: ' . $e->getMessage(), 0, $e);
        }

        $userinfo = new Userinfo($response);

        if ($tokens->idToken() !== null && $tokens->idToken()->sub() !== $userinfo->sub()) {
            throw new RuntimeException('Userinfo sub does not match id_token sub.');
        }

        return $userinfo;
    }
}
