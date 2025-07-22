<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Util\ParamsTrait;

final readonly class Userinfo
{
    use ParamsTrait;

    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(private array $claims)
    {
    }

    public function sub(): string
    {
        return $this->string('sub');
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims;
    }
}
