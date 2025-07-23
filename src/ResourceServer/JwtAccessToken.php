<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Util\JWT;

/**
 * JWT access token implementation
 */
final class JwtAccessToken extends AccessToken
{
    /**
     * Extract JWT claims
     *
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return JWT::claims($this->token);
    }
}
