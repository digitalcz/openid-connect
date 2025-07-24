<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Util\ClaimsTrait;
use DigitalCz\OpenIDConnect\Util\JWT;
use Stringable;
use UnexpectedValueException;

/**
 * OpenID Connect ID Token with user identity claims.
 */
final readonly class IdToken
{
    use ClaimsTrait;

    /**
     * @param string $token The raw JWT ID token string
     */
    public function __construct(
        private string $token,
    ) {
    }

    /**
     * Creates an IDToken instance from various input types.
     *
     * @param mixed $value The value to create IDToken from. Can be:
     *                     - string: JWT token string
     *                     - array: Must contain 'id_token' key with JWT string value
     *                     - Stringable: Will be converted to string
     * @return self The IDToken instance
     *
     * @throws UnexpectedValueException If the value cannot be converted to a valid JWT ID token
     */
    public static function from(mixed $value): self
    {
        if (is_array($value)) {
            if (!isset($value['id_token'])) {
                throw new UnexpectedValueException('Cannot create IDToken from array without "id_token" key');
            }

            $value = $value['id_token'];
        }

        if ($value instanceof Stringable) {
            $value = (string) $value;
        }

        if (!is_string($value)) {
            throw new UnexpectedValueException('Cannot create IDToken from ' . get_debug_type($value));
        }

        if (!JWT::validate($value)) {
            throw new UnexpectedValueException('Invalid JWT ID token format');
        }

        return new self($value);
    }

    /**
     * Attempts to create an IDToken instance from various input types.
     *
     * @param mixed $value The value to create IDToken from. Can be:
     *                     - string: JWT token string
     *                     - array: Must contain 'id_token' key with JWT string value
     *                     - Stringable: Will be converted to string
     * @return self|null The IDToken instance on success, null on failure
     */
    public static function tryFrom(mixed $value): ?self
    {
        try {
            return self::from($value);
        } catch (UnexpectedValueException) {
            return null;
        }
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
