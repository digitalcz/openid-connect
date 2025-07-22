<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Util\JWT;
use Stringable;

/**
 * Abstract token base class
 */
abstract class AccessToken implements Stringable
{
    public function __construct(
        protected readonly string $token,
    ) {
    }

    /**
     * Create token from response data
     *
     * @param mixed[] $responseData
     */
    public static function fromTokenResponse(array $responseData): ?self
    {
        $accessToken = $responseData['access_token'] ?? null;

        if (!is_string($accessToken)) {
            return null;
        }

        if (JWT::validate($accessToken)) {
            return new JwtAccessToken($accessToken);
        }

        return new OpaqueAccessToken($accessToken);
    }

    public function __toString(): string
    {
        return $this->token;
    }
}
