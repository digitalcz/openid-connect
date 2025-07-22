<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Util\JWT;

final class JwtAccessToken extends AccessToken
{
    /**
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return JWT::claims($this->token);
    }
}
