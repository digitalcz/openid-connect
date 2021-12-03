<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Token;

use DigitalCz\OpenIDConnect\JOSE\Claims;

final class Tokens
{
    public function __construct(
        private string $accessToken,
        private ?string $idToken,
        private ?string $refreshToken = null
    ) {
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getIdToken(): ?string
    {
        return $this->idToken;
    }

    public function getIdTokenClaims(): ?Claims
    {
        if ($this->getIdToken() === null) {
            return null;
        }

        return Claims::fromToken($this->getIdToken());
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }
}
