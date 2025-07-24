<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Util\JWT;
use Stringable;
use UnexpectedValueException;

/**
 * Abstract token base class
 */
abstract class AccessToken implements Stringable
{
    public function __construct(
        protected readonly string $token,
    ) {
    }

    /**
     * Creates an AccessToken instance from various input types.
     *
     * @param mixed $value The value to create AccessToken from. Can be:
     *                     - string: Access token string
     *                     - array: Must contain 'access_token' key with token string value
     *                     - Stringable: Will be converted to string
     * @return self The AccessToken instance (JWT or Opaque based on format)
     *
     * @throws UnexpectedValueException If the value cannot be converted to a valid access token
     */
    public static function from(mixed $value): self
    {
        if (is_array($value)) {
            if (!isset($value['access_token'])) {
                throw new UnexpectedValueException('Cannot create AccessToken from array without "access_token" key');
            }

            $value = $value['access_token'];
        }

        if ($value instanceof Stringable) {
            $value = (string) $value;
        }

        if (!is_string($value)) {
            throw new UnexpectedValueException('Cannot create AccessToken from ' . get_debug_type($value));
        }

        if ($value === '') {
            throw new UnexpectedValueException('Access token cannot be empty');
        }

        if (JWT::validate($value)) {
            return new JwtAccessToken($value);
        }

        return new OpaqueAccessToken($value);
    }

    /**
     * Attempts to create an AccessToken instance from various input types.
     *
     * @param mixed $value The value to create AccessToken from. Can be:
     *                     - string: Access token string
     *                     - array: Must contain 'access_token' key with token string value
     *                     - Stringable: Will be converted to string
     * @return self|null The AccessToken instance on success, null on failure
     */
    public static function tryFrom(mixed $value): ?self
    {
        try {
            return self::from($value);
        } catch (UnexpectedValueException) {
            return null;
        }
    }

    public function __toString(): string
    {
        return $this->token;
    }
}
