<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Util\ClaimsTrait;
use Throwable;

/**
 * Validated token result
 */
final readonly class ValidatedAccessToken
{
    use ClaimsTrait;

    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        private AccessToken $token,
        private array $claims,
    ) {
    }

    /**
     * Get subject claim
     */
    public function sub(): string
    {
        return $this->string('sub');
    }

    /**
     * Get issuer claim
     */
    public function iss(): string
    {
        return $this->string('iss');
    }

    /**
     * Get audience claim
     *
     * @return string|string[]
     */
    public function aud(): string|array
    {
        try {
            return $this->string('aud');
        } catch (Throwable) {
            return $this->strings('aud');
        }
    }

    /**
     * Get expiration time claim
     */
    public function exp(): int
    {
        return $this->integer('exp');
    }

    /**
     * Get scope claim
     */
    public function scope(): string
    {
        return $this->string('scope');
    }

    /**
     * Get all token claims
     *
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return $this->claims;
    }

    public function __toString(): string
    {
        return (string) $this->token;
    }
}
