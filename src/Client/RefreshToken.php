<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

/**
 * Refresh token representation
 */
final readonly class RefreshToken
{
    public function __construct(
        private string $token,
    ) {
    }

    /**
     * Creates refresh token from OAuth token response
     *
     * @param mixed[] $responseData
     */
    public static function fromTokenResponse(array $responseData): ?self
    {
        $refreshToken = $responseData['refresh_token'] ?? null;

        if (!is_string($refreshToken)) {
            return null;
        }

        return new self($refreshToken);
    }

    public function __toString(): string
    {
        return $this->token;
    }
}
