<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use InvalidArgumentException;
use Throwable;
use UnexpectedValueException;

final class JWT
{
    /**
     * @return array{header: array<string, mixed>, payload: array<string, mixed>, signature: string}
     *
     * @throws UnexpectedValueException
     */
    public static function parse(string $jwt): array
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new UnexpectedValueException('Invalid JWT - wrong number of parts');
        }

        [$header, $payload, $signature] = $parts;

        try {
            $header = Json::decode(Base64Url::decode($header));
        } catch (Throwable $e) {
            throw new UnexpectedValueException('Invalid JWT - invalid header encoding', 0, $e);
        }

        try {
            $payload = Json::decode(Base64Url::decode($payload));
        } catch (Throwable $e) {
            throw new UnexpectedValueException('Invalid JWT - invalid payload encoding', 0, $e);
        }

        try {
            $signature = Base64Url::decode($signature);
        } catch (InvalidArgumentException $e) {
            throw new UnexpectedValueException('Invalid JWT - invalid signature encoding', 0, $e);
        }

        return ['header' => $header, 'payload' => $payload, 'signature' => $signature];
    }

    public static function validate(string $jwt): bool
    {
        try {
            self::parse($jwt);

            return true;
        } catch (UnexpectedValueException $e) {
            return false;
        }
    }

    /**
     * @return array<string, mixed>
     */
    public static function header(string $jwt): array
    {
        return self::parse($jwt)['header'];
    }

    /**
     * @return array<string, mixed>
     */
    public static function claims(string $jwt): array
    {
        return self::parse($jwt)['payload'];
    }

    /**
     * @return mixed
     */
    public static function claim(string $jwt, string $claim)
    {
        return self::claims($jwt)[$claim] ?? null;
    }
}
