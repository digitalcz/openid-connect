<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use JsonException;
use Safe\Exceptions\JsonException as SafeJsonException;

use function Safe\json_decode;
use function Safe\json_encode;

final class Json
{
    /**
     * @param mixed[] $payload
     * @return string
     *
     * @throws SafeJsonException|JsonException
     */
    public static function encode(array $payload): string
    {
        return json_encode($payload, JSON_THROW_ON_ERROR);
    }

    /**
     * @param string $json
     * @return mixed[]
     *
     * @throws SafeJsonException|JsonException
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
