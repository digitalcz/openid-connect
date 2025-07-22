<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\Config;
use InvalidArgumentException;
use RuntimeException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final readonly class AuthorizationCode
{
    public function __construct(
        private Config $config,
        private HttpClientInterface $httpClient,
        private IdTokenValidator $validator,
    ) {
    }

    /**
     * @param array<string, string> $params
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

    public function refreshToken(Tokens $tokens): Tokens
    {
        if ($tokens->refreshToken() === null) {
            throw new InvalidArgumentException('Cannot refresh tokens without a refresh token.');
        }

        $issuerMetadata = $this->config->issuerMetadata();
        $clientMetadata = $this->config->clientMetadata();
        $tokenEndpoint = $issuerMetadata->tokenEndpoint();
        $options = [
            'body' => [
                'grant_type' => 'refresh_token',
                'refresh_token' => $tokens->refreshToken(),
            ],
        ];
        $authOptions = $clientMetadata->authenticationMethod()->asOptions($clientMetadata);
        $options = array_merge_recursive($options, $authOptions);
        $response = $this->httpClient->request('POST', $tokenEndpoint, $options);
        $result = $response->toArray();

        // If the refresh_token is not rotated, preserve the existing one
        $result['refresh_token'] ??= (string)$tokens->refreshToken();

        return Tokens::fromTokenResponse($result);
    }

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
