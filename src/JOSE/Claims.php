<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use DigitalCz\OpenIDConnect\Param\Params;
use DigitalCz\OpenIDConnect\Util\JWT;

final class Claims extends Params
{
    public static function fromToken(string $token): self
    {
        return new self(JWT::claims($token));
    }
}
