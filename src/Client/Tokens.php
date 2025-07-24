<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\ResourceServer\AccessToken;

/**
 * Container for all tokens received in OAuth flow
 */
final readonly class Tokens
{
    public function __construct(
        private ?AccessToken $accessToken = null,
        private ?RefreshToken $refreshToken = null,
        private ?IdToken $idToken = null,
        private ?string $scope = null,
        private ?string $tokenType = null,
        private ?int $expiresIn = null,
    ) {
    }

    /**
     * Creates tokens container from OAuth token response
     *
     * @param mixed[] $responseData
     */
    public static function fromTokenResponse(array $responseData): self
    {
        $scope = $responseData['scope'] ?? null;
        $scope = is_string($scope) ? $scope : null;
        $tokenType = $responseData['token_type'] ?? null;
        $tokenType = is_string($tokenType) ? $tokenType : null;
        $expiresIn = $responseData['expires_in'] ?? null;
        $expiresIn = is_int($expiresIn) ? $expiresIn : null;

        return new self(
            accessToken: AccessToken::tryFrom($responseData),
            refreshToken: RefreshToken::tryFrom($responseData),
            idToken: IdToken::tryFrom($responseData),
            scope: $scope,
            tokenType: $tokenType,
            expiresIn: $expiresIn,
        );
    }

    public function accessToken(): ?AccessToken
    {
        return $this->accessToken;
    }

    public function refreshToken(): ?RefreshToken
    {
        return $this->refreshToken;
    }

    public function idToken(): ?IdToken
    {
        return $this->idToken;
    }

    public function scope(): ?string
    {
        return $this->scope;
    }

    public function tokenType(): ?string
    {
        return $this->tokenType;
    }

    public function expiresIn(): ?int
    {
        return $this->expiresIn;
    }
}
