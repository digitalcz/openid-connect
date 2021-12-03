<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use DigitalCz\OpenIDConnect\Param\CallbackChecks;

interface ClaimsCheckerInterface
{
    public function check(Claims $claims, CallbackChecks $checks): void;
}
