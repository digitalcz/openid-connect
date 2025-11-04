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
 * Represents a validated logout token containing claims about the logout event.
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
     *                     - Stringable: Will be converted to string
     * @return self The LogoutToken instance
     *
     * @throws UnexpectedValueException If the value cannot be converted to a valid JWT logout token
     */
    public static function from(mixed $value): self
    {
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

    /**
     * Get the issuer identifier.
     *
     * @return string The issuer URL
     */
    public function issuer(): string
    {
        return $this->string('iss');
    }

    /**
     * Get the audience (client ID).
     *
     * @return string|string[] The audience claim
     */
    public function audience(): string|array
    {
        $aud = $this->get('aud');

        if (is_array($aud)) {
            return $this->strings('aud');
        }

        return $this->string('aud');
    }

    /**
     * Get the subject identifier (user ID).
     *
     * @return string|null The subject identifier, or null if not present
     */
    public function subject(): ?string
    {
        return $this->has('sub') ? $this->string('sub') : null;
    }

    /**
     * Get the session ID.
     *
     * @return string|null The session identifier, or null if not present
     */
    public function sessionId(): ?string
    {
        return $this->has('sid') ? $this->string('sid') : null;
    }

    /**
     * Get the issued-at timestamp.
     *
     * @return int The timestamp when the token was issued
     */
    public function issuedAt(): int
    {
        return $this->integer('iat');
    }

    /**
     * Get the JWT ID (unique identifier for this token).
     *
     * @return string The JWT ID
     */
    public function jwtId(): string
    {
        return $this->string('jti');
    }

    /**
     * Get the events claim.
     *
     * @return array<string, mixed> The events claim containing logout event
     */
    public function events(): array
    {
        $events = $this->get('events');

        if (!is_array($events)) {
            throw new UnexpectedValueException('Events claim must be an array');
        }

        return $events;
    }

    /**
     * Get all JWT claims from the logout token.
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
     * @return string The raw JWT logout token
     */
    public function __toString(): string
    {
        return $this->token;
    }
}
