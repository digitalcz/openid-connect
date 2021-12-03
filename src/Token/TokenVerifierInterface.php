<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Token;

use DigitalCz\OpenIDConnect\Param\CallbackChecks;

interface TokenVerifierInterface
{
    public function verify(string $token, CallbackChecks $checks): void;
}
