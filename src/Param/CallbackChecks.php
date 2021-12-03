<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Param;

final class CallbackChecks
{
    public function __construct(private ?string $state = null, private ?string $nonce = null)
    {
    }

    public function state(): ?string
    {
        return $this->state;
    }

    public function nonce(): ?string
    {
        return $this->nonce;
    }
}
