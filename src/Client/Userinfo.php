<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Util\ParamsTrait;

/**
 * User profile information from userinfo endpoint
 */
final readonly class Userinfo
{
    use ParamsTrait;

    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(private array $claims)
    {
    }

    /** Returns subject identifier */
    public function sub(): string
    {
        return $this->string('sub');
    }

    /**
     * Returns all user claims
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims;
    }
}
