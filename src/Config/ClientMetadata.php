<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\Client\ClientAuthenticator;
use DigitalCz\OpenIDConnect\Util\PkceMethod;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Psr\Clock\ClockInterface;

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
        private ?string $privateKey = null,
        private ?JWK $privateKeyJwk = null,
        private ?string $tokenEndpointAuthSigningAlg = null,
        private ?string $clientAssertionAudience = null,
        private ?ClockInterface $clock = null,
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

    public function privateKey(): ?string
    {
        return $this->privateKey;
    }

    public function privateKeyJwk(): ?JWK
    {
        return $this->privateKeyJwk;
    }

    public function tokenEndpointAuthSigningAlg(): ?string
    {
        return $this->tokenEndpointAuthSigningAlg;
    }

    public function clientAssertionAudience(): ?string
    {
        return $this->clientAssertionAudience;
    }

    public function clock(): ClockInterface
    {
        return $this->clock ?? new SimpleClock();
    }

    /**
     * Apply client authentication credentials to HTTP request options
     *
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     *
     * @deprecated Use ClientAuthenticator::applyAuthentication() instead. This method will be removed in v2.0.
     */
    public function applyCredentials(array $options): array
    {
        // JWT authentication methods require proper IssuerMetadata with token_endpoint
        $jwtMethods = [AuthenticationMethod::ClientSecretJwt, AuthenticationMethod::PrivateKeyJwt];

        if (in_array($this->authenticationMethod, $jwtMethods, true)) {
            throw new InvalidArgumentException(
                'JWT authentication methods (client_secret_jwt, private_key_jwt) are not supported by this deprecated method. ' .
                'Use ClientAuthenticator with proper IssuerMetadata containing token_endpoint instead.',
            );
        }

        return new ClientAuthenticator($this, new IssuerMetadata([]))->applyAuthentication($options);
    }
}
