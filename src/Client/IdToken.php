<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Util\JWT;
use DigitalCz\OpenIDConnect\Util\ParamsTrait;

final readonly class IdToken
{
    use ParamsTrait;

    public function __construct(
        private string $token,
    ) {
    }

    /**
     * @param mixed[] $responseData
     */
    public static function fromTokenResponse(array $responseData): ?self
    {
        $idToken = $responseData['id_token'] ?? null;

        if (!is_string($idToken)) {
            return null;
        }

        if (JWT::validate($idToken)) {
            return new self($idToken);
        }

        return null;
    }

    public function sub(): string
    {
        return $this->string('sub');
    }

    public function nonce(): string
    {
        return $this->string('nonce');
    }

    /**
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return JWT::claims($this->token);
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims();
    }

    public function __toString(): string
    {
        return $this->token;
    }
}
