<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;

/**
 * Interface for ID Token validation implementations.
 *
 * Defines the contract for validating OpenID Connect ID Tokens. Implementations
 * are responsible for verifying token signatures, validating claims (such as
 * issuer, audience, expiration), and ensuring the token meets security requirements.
 *
 * This interface allows for different validation strategies, such as JWT-based
 * validation with JWKS or other token validation mechanisms.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 */
interface IdTokenValidator
{
    /**
     * @throws InvalidTokenException
     */
    public function validate(IdToken $token, ?string $nonce = null): void;
}
