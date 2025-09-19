<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Util\JwtClientAssertionGenerator;
use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * Handles client authentication for OAuth2/OIDC requests
 */
final readonly class ClientAuthenticator
{
    public function __construct(
        private ClientMetadata $clientMetadata,
        private IssuerMetadata $issuerMetadata,
    ) {
    }

    /**
     * Apply client authentication credentials to HTTP request options
     *
     * Note: For JWT authentication methods, the token endpoint URL is always used as the audience
     * in the client_assertion JWT, regardless of which endpoint is being called (RFC 7523).
     *
     * @param array<string, mixed> $options HTTP request options
     * @return array<string, mixed> Modified HTTP request options with authentication
     */
    public function applyAuthentication(array $options): array
    {
        switch ($this->clientMetadata->authenticationMethod()) {
            case AuthenticationMethod::ClientSecretPost:
                $options['body'] ??= [];
                assert(is_array($options['body']));
                $options['body']['client_id'] ??= $this->clientMetadata->clientId();
                $options['body']['client_secret'] ??= $this->clientMetadata->clientSecret();

                return $options;
            case AuthenticationMethod::ClientSecretBasic:
                $options['auth_basic'] ??= [$this->clientMetadata->clientId(), $this->clientMetadata->clientSecret() ?? ''];

                return $options;
            case AuthenticationMethod::ClientSecretJwt:
                return $this->applyClientSecretJwtAuthentication($options);
            case AuthenticationMethod::PrivateKeyJwt:
                return $this->applyPrivateKeyJwtAuthentication($options);
            case AuthenticationMethod::None:
                $options['body'] ??= [];
                assert(is_array($options['body']));
                $options['body']['client_id'] ??= $this->clientMetadata->clientId();

                return $options;
        }
    }

    /**
     * Apply client_secret_jwt authentication credentials
     *
     * @param array<string, mixed> $options HTTP request options
     * @return array<string, mixed> Modified HTTP request options with JWT authentication
     */
    private function applyClientSecretJwtAuthentication(array $options): array
    {
        if ($this->clientMetadata->clientSecret() === null) {
            throw new InvalidArgumentException('Client secret is required for client_secret_jwt authentication');
        }

        $options['body'] ??= [];
        assert(is_array($options['body']));

        $generator = new JwtClientAssertionGenerator($this->clientMetadata->clock());
        $algorithm = $this->clientMetadata->tokenEndpointAuthSigningAlg() ?? 'HS256';
        $jwk = JWKFactory::createFromSecret($this->clientMetadata->clientSecret());

        $clientAssertion = $generator->generateJwt(
            $this->clientMetadata->clientId(),
            $this->issuerMetadata->tokenEndpoint(),
            $jwk,
            $algorithm,
            300,
        );

        $options['body']['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        $options['body']['client_assertion'] = $clientAssertion;

        return $options;
    }

    /**
     * Apply private_key_jwt authentication credentials
     *
     * @param array<string, mixed> $options HTTP request options
     * @return array<string, mixed> Modified HTTP request options with JWT authentication
     */
    private function applyPrivateKeyJwtAuthentication(array $options): array
    {
        $options['body'] ??= [];
        assert(is_array($options['body']));

        $generator = new JwtClientAssertionGenerator($this->clientMetadata->clock());
        $algorithm = $this->clientMetadata->tokenEndpointAuthSigningAlg() ?? 'RS256';

        if ($this->clientMetadata->privateKeyJwk() !== null) {
            $jwk = $this->clientMetadata->privateKeyJwk();
        } elseif ($this->clientMetadata->privateKey() !== null) {
            $jwk = JWKFactory::createFromKey($this->clientMetadata->privateKey());
        } else {
            throw new InvalidArgumentException('Private key or JWK is required for private_key_jwt authentication');
        }

        $clientAssertion = $generator->generateJwt(
            $this->clientMetadata->clientId(),
            $this->issuerMetadata->tokenEndpoint(),
            $jwk,
            $algorithm,
            300,
        );

        $options['body']['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        $options['body']['client_assertion'] = $clientAssertion;

        return $options;
    }
}
