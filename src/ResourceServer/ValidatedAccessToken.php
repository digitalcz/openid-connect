<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Util\ParamsTrait;
use Throwable;

final readonly class ValidatedAccessToken
{
    use ParamsTrait;

    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        private AccessToken $token,
        private array $claims,
    ) {
    }

    public function sub(): string
    {
        return $this->string('sub');
    }

    public function iss(): string
    {
        return $this->string('iss');
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

    public function exp(): int
    {
        return $this->integer('exp');
    }

    public function scope(): string
    {
        return $this->string('scope');
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims;
    }

    public function __toString(): string
    {
        return (string) $this->token;
    }
}
