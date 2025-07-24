<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Util\ClaimsTrait;
use DigitalCz\OpenIDConnect\Util\JWT;
use Throwable;

/**
 * JWT access token implementation
 */
final class JwtAccessToken extends AccessToken
{
    use ClaimsTrait;

    public function iss(): string
    {
        return $this->string('iss');
    }

    public function exp(): int
    {
        return $this->integer('exp');
    }

    public function sub(): string
    {
        return $this->string('sub');
    }

    /**
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

    public function iat(): int
    {
        return $this->integer('iat');
    }

    public function jti(): string
    {
        return $this->string('jti');
    }

    public function nbf(): int
    {
        return $this->integer('nbf');
    }

    public function scope(): string
    {
        return $this->string('scope');
    }

    public function clientId(): string
    {
        return $this->string('client_id');
    }

    /**
     * Extract JWT claims
     *
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return JWT::claims($this->token);
    }
}
