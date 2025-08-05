<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\Util\PkceMethod;
use InvalidArgumentException;

/**
 * Client configuration value object
 */
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
        private ?PkceMethod $pkceMethod = PkceMethod::S256,
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

    public function pkceMethod(): ?PkceMethod
    {
        return $this->pkceMethod;
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function applyCredentials(array $options): array
    {
        switch ($this->authenticationMethod) {
            case AuthenticationMethod::ClientSecretPost:
                $options['body'] ??= [];
                assert(is_array($options['body']));
                $options['body']['client_id'] ??= $this->clientId;
                $options['body']['client_secret'] = $this->clientSecret;

                return $options;
            case AuthenticationMethod::ClientSecretBasic:
                $options['auth_basic'] ??= [$this->clientId, $this->clientSecret ?? ''];

                return $options;
            case AuthenticationMethod::None:
                $options['body'] ??= [];
                assert(is_array($options['body']));
                $options['body']['client_id'] ??= $this->clientId;

                return $options;
        }
    }
}
