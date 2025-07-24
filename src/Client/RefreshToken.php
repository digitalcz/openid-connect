<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use Stringable;
use UnexpectedValueException;

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
     * Creates a RefreshToken instance from various input types.
     *
     * @param mixed $value The value to create RefreshToken from. Can be:
     *                     - string: Refresh token string
     *                     - array: Must contain 'refresh_token' key with token string value
     *                     - Stringable: Will be converted to string
     * @return self The RefreshToken instance
     *
     * @throws UnexpectedValueException If the value cannot be converted to a valid refresh token
     */
    public static function from(mixed $value): self
    {
        if (is_array($value)) {
            if (!isset($value['refresh_token'])) {
                throw new UnexpectedValueException('Cannot create RefreshToken from array without "refresh_token" key');
            }

            $value = $value['refresh_token'];
        }

        if ($value instanceof Stringable) {
            $value = (string) $value;
        }

        if (!is_string($value)) {
            throw new UnexpectedValueException('Cannot create RefreshToken from ' . get_debug_type($value));
        }

        if ($value === '') {
            throw new UnexpectedValueException('Refresh token cannot be empty');
        }

        return new self($value);
    }

    /**
     * Attempts to create a RefreshToken instance from various input types.
     *
     * @param mixed $value The value to create RefreshToken from. Can be:
     *                     - string: Refresh token string
     *                     - array: Must contain 'refresh_token' key with token string value
     *                     - Stringable: Will be converted to string
     * @return self|null The RefreshToken instance on success, null on failure
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
