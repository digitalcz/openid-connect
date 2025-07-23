<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use InvalidArgumentException;
use Throwable;
use UnexpectedValueException;

/**
 * JWT parsing and validation utilities
 */
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

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        try {
            /** @var array<string, mixed> $header */
            $header = Json::decode(Base64Url::decode($encodedHeader));
        } catch (Throwable $e) {
            throw new UnexpectedValueException('Invalid JWT - invalid header encoding', 0, $e);
        }

        try {
            /** @var array<string, mixed> $payload */
            $payload = Json::decode(Base64Url::decode($encodedPayload));
        } catch (Throwable $e) {
            throw new UnexpectedValueException('Invalid JWT - invalid payload encoding', 0, $e);
        }

        try {
            $signature = Base64Url::decode($encodedSignature);
        } catch (InvalidArgumentException $e) {
            throw new UnexpectedValueException('Invalid JWT - invalid signature encoding', 0, $e);
        }

        return ['header' => $header, 'payload' => $payload, 'signature' => $signature];
    }

    /**
     * Validate JWT format without signature verification
     */
    public static function validate(string $jwt): bool
    {
        try {
            self::parse($jwt);

            return true;
        } catch (UnexpectedValueException) {
            return false;
        }
    }

    /**
     * Extract JWT header
     *
     * @return array<string, mixed>
     */
    public static function header(string $jwt): array
    {
        return self::parse($jwt)['header'];
    }

    /**
     * Extract JWT payload claims
     *
     * @return array<string, mixed>
     */
    public static function claims(string $jwt): array
    {
        return self::parse($jwt)['payload'];
    }

    /**
     * Extract specific claim from JWT
     *
     * @return mixed
     */
    public static function claim(string $jwt, string $claim)
    {
        return self::claims($jwt)[$claim] ?? null;
    }
}
