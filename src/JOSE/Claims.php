<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use DigitalCz\OpenIDConnect\Exception\RuntimeException;
use DigitalCz\OpenIDConnect\Param\Params;
use DigitalCz\OpenIDConnect\Util\Base64;
use DigitalCz\OpenIDConnect\Util\Json;

final class Claims extends Params
{
    public static function fromToken(string $token): self
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new RuntimeException('Invalid token');
        }

        $payload = Base64::urlDecode($parts[1]);

        return new self(Json::decode($payload));
    }
}
