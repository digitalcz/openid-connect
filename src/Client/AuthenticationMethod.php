<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\ClientMetadata;

/**
 * OAuth2 client authentication methods for token requests.
 */
enum AuthenticationMethod: string
{
    /** HTTP Basic authentication with client credentials. */
    case ClientSecretBasic = 'client_secret_basic';

    /** Client credentials sent in HTTP request body. */
    case ClientSecretPost = 'client_secret_post';

    /** Public client with no authentication. */
    case None = 'none';

    /**
     * Convert authentication method to HTTP client options.
     *
     * @param ClientMetadata $clientMetadata Client metadata with credentials
     * @return array<string, mixed> HTTP client options
     *
     * @deprecated Use ClientMetadata::applyCredentials() instead. This method will be removed in v2.0.
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
