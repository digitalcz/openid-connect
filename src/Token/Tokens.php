<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Token;

use DigitalCz\OpenIDConnect\JOSE\Claims;
use DigitalCz\OpenIDConnect\Param\Params;

final class Tokens extends Params
{
    public function __construct(array $parameters = [])
    {
        if (isset($parameters['expires_in']) && !isset($parameters['expires'])) {
            $parameters['expires'] = time() + $parameters['expires_in'];
        }

        parent::__construct($parameters);
    }

    public function getAccessToken(): string
    {
        return $this->getString('access_token');
    }

    public function getIdToken(): ?string
    {
        return $this->get('id_token');
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
        return $this->get('refresh_token');
    }

    public function getExpiresIn(): ?int
    {
        return $this->get('expires_in', 0);
    }

    public function getExpires(): int
    {
        return $this->getInt('expires', 0);
    }

    public function getScope(): ?string
    {
        return $this->get('scope');
    }

    public function isExpired(): bool
    {
        return $this->getExpires() <= time();
    }
}
