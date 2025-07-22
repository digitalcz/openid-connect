<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;

final readonly class ClientMetadata
{
    /**
     * @param list<string> $defaultScopes
     */
    public function __construct(
        private string $clientId,
        private ?string $clientSecret = null,
        private ?string $redirectUri = null,
        private array $defaultScopes = ['openid', 'profile', 'email'],
        private AuthenticationMethod $authenticationMethod = AuthenticationMethod::ClientSecretPost,
    ) {
    }

    public function clientId(): string
    {
        return $this->clientId;
    }

    public function clientSecret(): ?string
    {
        return $this->clientSecret;
    }

    public function redirectUri(): ?string
    {
        return $this->redirectUri;
    }

    /**
     * @return list<string>
     */
    public function defaultScopes(): array
    {
        return $this->defaultScopes;
    }

    public function authenticationMethod(): AuthenticationMethod
    {
        return $this->authenticationMethod;
    }
}
