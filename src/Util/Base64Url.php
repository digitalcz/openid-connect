<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use InvalidArgumentException;

final class Base64Url
{
    /**
     * Encode url-safe base64 string
     */
    public static function encode(string $data, bool $usePadding = false): string
    {
        $encoded = strtr(base64_encode($data), '+/', '-_');

        return $usePadding === true ? $encoded : rtrim($encoded, '=');
    }

    /**
     * Decode url-safe base64 string
     */
    public static function decode(string $string): string
    {
        $decoded = base64_decode(strtr($string, '-_', '+/'), true);

        if ($decoded === false) {
            throw new InvalidArgumentException('Invalid base64url string',);
        }

        return $decoded;
    }
}
