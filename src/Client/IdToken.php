<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Util\JWT;
use DigitalCz\OpenIDConnect\Util\ParamsTrait;

/**
 * OpenID Connect ID Token with user identity claims.
 */
final readonly class IdToken
{
    use ParamsTrait;

    /**
     * @param string $token The raw JWT ID token string
     */
    public function __construct(
        private string $token,
    ) {
    }

    /**
     * Create ID Token from token response data.
     *
     * Factory method that extracts and validates the ID token from an OAuth2/OIDC
     * token response. Returns null if no ID token is present or if the token
     * format is invalid.
     *
     * @param mixed[] $responseData The token response data from the authorization server
     * @return self|null The ID token instance, or null if not present or invalid
     */
    public static function fromTokenResponse(array $responseData): ?self
    {
        $idToken = $responseData['id_token'] ?? null;

        if (!is_string($idToken)) {
            return null;
        }

        if (JWT::validate($idToken)) {
            return new self($idToken);
        }

        return null;
    }

    /**
     * Get the subject identifier (user ID).
     *
     * Returns the subject identifier from the ID token, which uniquely identifies
     * the authenticated user within the issuer's domain.
     *
     * @return string The subject identifier (user ID)
     */
    public function sub(): string
    {
        return $this->string('sub');
    }

    /**
     * Get the nonce value.
     *
     * Returns the nonce value that was included in the authentication request
     * for CSRF protection and request correlation.
     *
     * @return string The nonce value
     */
    public function nonce(): string
    {
        return $this->string('nonce');
    }

    /**
     * Get all JWT claims from the ID token.
     *
     * Returns the complete set of claims contained in the ID token payload.
     * This includes both standard OpenID Connect claims and any custom claims
     * added by the identity provider.
     *
     * @return array<string, mixed> All JWT claims as an associative array
     */
    public function claims(): array
    {
        return JWT::claims($this->token);
    }

    /**
     * Get all JWT claims from the ID token (alias for claims()).
     *
     * Implementation of the ParamsTrait abstract method. This method is
     * equivalent to claims() and is used by the trait for parameter access.
     *
     * @return array<string, mixed> All JWT claims as an associative array
     */
    public function all(): array
    {
        return $this->claims();
    }

    /**
     * Get the raw JWT token string.
     *
     * Returns the original JWT token string that can be used for Bearer
     * authentication or further processing.
     *
     * @return string The raw JWT ID token
     */
    public function __toString(): string
    {
        return $this->token;
    }
}
