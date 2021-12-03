<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

interface SignatureCheckerInterface
{
    public function check(string $token): void;
}
