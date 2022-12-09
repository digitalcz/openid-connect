<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use DigitalCz\OpenIDConnect\Param\ClaimsChecks;

interface ClaimsCheckerInterface
{
    public function check(Claims $claims, ClaimsChecks $checks): void;
}
