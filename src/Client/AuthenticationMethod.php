<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\ClientMetadata;

/**
 * OAuth2 client authentication methods for token requests.
 */
enum AuthenticationMethod
{
    /** HTTP Basic authentication with client credentials. */
    case ClientSecretBasic;

    /** Client credentials sent in HTTP request body. */
    case ClientSecretPost;

    /** Public client with no authentication. */
    case None;

    /**
     * Convert authentication method to HTTP client options.
     *
     * @param ClientMetadata $clientMetadata Client metadata with credentials
     * @return array<string, mixed> HTTP client options
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
