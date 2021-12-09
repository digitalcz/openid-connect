<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Token;

use DigitalCz\OpenIDConnect\JOSE\Claims;
use DigitalCz\OpenIDConnect\Param\Params;

final class Tokens extends Params
{
    public const ACCESS_TOKEN = 'access_token';
    public const REFRESH_TOKEN = 'refresh_token';
    public const ID_TOKEN = 'id_token';
    public const EXPIRES_IN = 'expires_in';
    public const EXPIRES = 'expires';
    public const SCOPE = 'scope';

    public function __construct(array $parameters = [])
    {
        if (isset($parameters[self::EXPIRES_IN]) && !isset($parameters[self::EXPIRES])) {
            $parameters[self::EXPIRES] = time() + $parameters[self::EXPIRES_IN];
        }

        parent::__construct($parameters);
    }

    public function getAccessToken(): string
    {
        return $this->getString(self::ACCESS_TOKEN);
    }

    public function getIdToken(): ?string
    {
        return $this->get(self::ID_TOKEN);
    }

    public function getIdTokenClaims(): ?Claims
    {
        if ($this->getIdToken() === null) {
            return null;
        }

        return Claims::fromToken($this->getIdToken());
    }

    public function getRefreshToken(): ?string
    {
        return $this->get(self::REFRESH_TOKEN);
    }

    public function getExpiresIn(): ?int
    {
        return $this->get(self::EXPIRES_IN, 0);
    }

    public function getExpires(): int
    {
        return $this->getInt(self::EXPIRES, 0);
    }

    public function getScope(): ?string
    {
        return $this->get(self::SCOPE);
    }

    public function isExpired(): bool
    {
        return $this->getExpires() <= time();
    }
}
