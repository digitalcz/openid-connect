<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Client\AuthorizationCode;
use DigitalCz\OpenIDConnect\Client\ClientCredentials;
use DigitalCz\OpenIDConnect\ResourceServer\ResourceServer;

/**
 * Main OpenID Connect client facade.
 */
final readonly class Oidc
{
    public function __construct(
        private AuthorizationCode $authorizationCode,
        private ClientCredentials $clientCredentials,
        private ResourceServer $resourceServer,
    ) {
    }

    public function authorizationCode(): AuthorizationCode
    {
        return $this->authorizationCode;
    }

    public function clientCredentials(): ClientCredentials
    {
        return $this->clientCredentials;
    }

    public function resourceServer(): ResourceServer
    {
        return $this->resourceServer;
    }
}
