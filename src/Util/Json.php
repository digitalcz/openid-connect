<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use JsonException;

final class Json
{
    /**
     * @param mixed[] $payload
     *
     * @throws JsonException
     */
    public static function encode(array $payload): string
    {
        return json_encode($payload, JSON_THROW_ON_ERROR);
    }

    /**
     * @return mixed[]
     *
     * @throws JsonException
     */
    public static function decode(string $json): array
    {
        $result = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($result)) {
            throw new JsonException('Invalid JSON');
        }

        return $result;
    }
}
