<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Token;

use DigitalCz\OpenIDConnect\Param\ClaimsChecks;

interface TokenVerifierInterface
{
    public function verify(string $token, ClaimsChecks $checks): void;
}
