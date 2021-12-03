<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use DigitalCz\OpenIDConnect\Exception\RuntimeException;
use DigitalCz\OpenIDConnect\Param\Params;
use DigitalCz\OpenIDConnect\Util\Json;

use function Safe\base64_decode;

final class Claims extends Params
{
    public static function fromToken(string $token): self
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new RuntimeException('Invalid token');
        }

        $payload = base64_decode($parts[1], true);

        return new self(Json::decode($payload));
    }
}
