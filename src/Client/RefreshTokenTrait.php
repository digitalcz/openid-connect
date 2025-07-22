<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use InvalidArgumentException;

trait RefreshTokenTrait
{
    /**
     * Refresh access tokens using refresh token.
     *
     * @param Tokens $tokens Current tokens with refresh token
     * @return Tokens New tokens with fresh access token
     */
    public function doRefreshToken(Tokens $tokens): Tokens
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
}
