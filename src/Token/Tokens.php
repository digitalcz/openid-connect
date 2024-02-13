<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Token;

use DigitalCz\OpenIDConnect\Param\Params;

final class Tokens extends Params
{
    public const ACCESS_TOKEN = 'access_token';
    public const REFRESH_TOKEN = 'refresh_token';
    public const ID_TOKEN = 'id_token';
    public const EXPIRES_IN = 'expires_in';
    public const EXPIRES = 'expires';
    public const SCOPE = 'scope';

    /**
     * @param array<string, int|string|null> $parameters
     */
    public function __construct(array $parameters = [])
    {
        if (isset($parameters[self::EXPIRES_IN]) && !isset($parameters[self::EXPIRES])) {
            $parameters[self::EXPIRES] = time() + (int)$parameters[self::EXPIRES_IN];
        }

        parent::__construct($parameters);
    }

    public function accessToken(): string
    {
        return $this->getString(self::ACCESS_TOKEN);
    }

    public function idToken(): ?string
    {
        return $this->get(self::ID_TOKEN);
    }

    public function refreshToken(): ?string
    {
        return $this->get(self::REFRESH_TOKEN);
    }

    public function expiresIn(): ?int
    {
        return $this->get(self::EXPIRES_IN, 0);
    }

    public function expires(): int
    {
        return $this->getInt(self::EXPIRES, 0);
    }

    public function scope(): ?string
    {
        return $this->get(self::SCOPE);
    }

    public function isExpired(): bool
    {
        return $this->expires() <= time();
    }
}
