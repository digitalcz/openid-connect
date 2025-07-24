<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Util\ClaimsTrait;

/**
 * User profile information from userinfo endpoint
 */
final readonly class Userinfo
{
    use ClaimsTrait;

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
    public function claims(): array
    {
        return $this->claims;
    }
}
