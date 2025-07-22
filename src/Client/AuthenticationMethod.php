<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\ClientMetadata;

enum AuthenticationMethod
{
    case ClientSecretBasic;
    case ClientSecretPost;
    case None;

    /**
     * @return array<string, mixed>
     */
    public function asOptions(ClientMetadata $clientMetadata): array
    {
        return match ($this) {
            self::ClientSecretPost => [
                'body' => [
                    'client_id' => $clientMetadata->clientId(),
                    'client_secret' => $clientMetadata->clientSecret(),
                ],
            ],
            self::ClientSecretBasic => [
                'auth_basic' => [$clientMetadata->clientId(), $clientMetadata->clientSecret() ?? ''],
            ],
            self::None => [
                'body' => [
                    'client_id' => $clientMetadata->clientId(),
                ],
            ],
        };
    }
}
