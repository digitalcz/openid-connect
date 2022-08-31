<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use function Safe\base64_decode;

final class Base64
{
    /**
     * Decode base64 string
     */
    public static function decode(string $data): string
    {
        return base64_decode($data, true);
    }

    /**
     * Decode url-safe base64 string
     */
    public static function urlDecode(string $data): string
    {
        return self::decode(strtr($data, '._-', '+/='));
    }
}
