<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DigitalCz\OpenIDConnect\Util\ClaimsTrait;
use DigitalCz\OpenIDConnect\Util\JWT;
use Stringable;
use UnexpectedValueException;

/**
 * OpenID Connect Back-Channel Logout Token.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html
 */
final readonly class LogoutToken
{
    use ClaimsTrait;

    /**
     * @param string $token The raw JWT logout token string
     */
    public function __construct(
        private string $token,
    ) {
    }

    /**
     * Creates a LogoutToken instance from various input types.
     *
     * @param mixed $value The value to create LogoutToken from. Can be:
     *                     - string: JWT token string
     *                     - array: Must contain 'logout_token' key with JWT string value
     *                     - Stringable: Will be converted to string
     *
     * @throws UnexpectedValueException If the value cannot be converted to a valid JWT logout token
     */
    public static function from(mixed $value): self
    {
        if (is_array($value)) {
            if (!isset($value['logout_token'])) {
                throw new UnexpectedValueException('Cannot create LogoutToken from array without "logout_token" key');
            }

            $value = $value['logout_token'];
        }

        if ($value instanceof Stringable) {
            $value = (string) $value;
        }

        if (!is_string($value)) {
            throw new UnexpectedValueException('Cannot create LogoutToken from ' . get_debug_type($value));
        }

        if (!JWT::validate($value)) {
            throw new UnexpectedValueException('Invalid JWT logout token format');
        }

        return new self($value);
    }

    public static function tryFrom(mixed $value): ?self
    {
        try {
            return self::from($value);
        } catch (UnexpectedValueException) {
            return null;
        }
    }

    public function iss(): string
    {
        return $this->string('iss');
    }

    /**
     * Get the audience claim.
     *
     * Logout tokens MAY contain either a single string or an array of strings.
     *
     * @return string|list<string>
     */
    public function aud(): string|array
    {
        $value = $this->get('aud');

        if (is_string($value)) {
            return $value;
        }

        return array_values($this->strings('aud'));
    }

    public function iat(): int
    {
        return $this->integer('iat');
    }

    public function jti(): string
    {
        return $this->string('jti');
    }

    /**
     * Subject identifier. Either `sub` or `sid` MUST be present; both MAY be.
     */
    public function sub(): ?string
    {
        return $this->has('sub') ? $this->string('sub') : null;
    }

    /**
     * Session identifier. Either `sub` or `sid` MUST be present; both MAY be.
     */
    public function sid(): ?string
    {
        return $this->has('sid') ? $this->string('sid') : null;
    }

    /**
     * @return array<string, mixed>
     */
    public function events(): array
    {
        $value = $this->get('events');

        if (!is_array($value)) {
            throw new UnexpectedValueException('Claim "events" is required and must be an object.');
        }

        /** @var array<string, mixed> $value */
        return $value;
    }

    /**
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return JWT::claims($this->token);
    }

    public function __toString(): string
    {
        return $this->token;
    }
}
