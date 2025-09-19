<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\Util\JwtClientAssertionGenerator;
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
        private ?string $jwksUri = null,
        private ?string $tokenEndpointAuthSigningAlg = null,
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

    public function jwksUri(): ?string
    {
        return $this->jwksUri;
    }

    public function tokenEndpointAuthSigningAlg(): ?string
    {
        return $this->tokenEndpointAuthSigningAlg;
    }

    public function clock(): ClockInterface
    {
        return $this->clock ?? new SimpleClock();
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function applyCredentials(array $options, ?string $tokenEndpoint = null): array
    {
        switch ($this->authenticationMethod) {
            case AuthenticationMethod::ClientSecretPost:
                $options['body'] ??= [];
                assert(is_array($options['body']));
                $options['body']['client_id'] ??= $this->clientId;
                $options['body']['client_secret'] ??= $this->clientSecret;

                return $options;
            case AuthenticationMethod::ClientSecretBasic:
                $options['auth_basic'] ??= [$this->clientId, $this->clientSecret ?? ''];

                return $options;
            case AuthenticationMethod::ClientSecretJwt:
                return $this->applyJwtCredentials($options, $tokenEndpoint, true);
            case AuthenticationMethod::PrivateKeyJwt:
                return $this->applyJwtCredentials($options, $tokenEndpoint, false);
            case AuthenticationMethod::None:
                $options['body'] ??= [];
                assert(is_array($options['body']));
                $options['body']['client_id'] ??= $this->clientId;

                return $options;
        }
    }

    /**
     * Apply JWT-based authentication credentials
     *
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    private function applyJwtCredentials(array $options, ?string $tokenEndpoint, bool $useSecret): array
    {
        if ($tokenEndpoint === null) {
            throw new InvalidArgumentException('Token endpoint URL is required for JWT authentication');
        }

        $options['body'] ??= [];
        assert(is_array($options['body']));

        $generator = new JwtClientAssertionGenerator($this->clock());

        if ($useSecret) {
            if ($this->clientSecret === null) {
                throw new InvalidArgumentException('Client secret is required for client_secret_jwt authentication');
            }

            $algorithm = $this->tokenEndpointAuthSigningAlg ?? 'HS256';
            $clientAssertion = $generator->generateWithSecret(
                $this->clientId,
                $tokenEndpoint,
                $this->clientSecret,
                $algorithm,
            );
        } else {
            $algorithm = $this->tokenEndpointAuthSigningAlg ?? 'RS256';

            if ($this->privateKeyJwk !== null) {
                $clientAssertion = $generator->generateWithJwk(
                    $this->clientId,
                    $tokenEndpoint,
                    $this->privateKeyJwk,
                    $algorithm,
                );
            } elseif ($this->privateKey !== null) {
                $clientAssertion = $generator->generateWithPrivateKey(
                    $this->clientId,
                    $tokenEndpoint,
                    $this->privateKey,
                    $algorithm,
                );
            } else {
                throw new InvalidArgumentException('Private key or JWK is required for private_key_jwt authentication');
            }
        }

        $options['body']['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        $options['body']['client_assertion'] = $clientAssertion;

        return $options;
    }
}
