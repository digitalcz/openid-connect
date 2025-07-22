<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Client\AuthorizationCode;
use DigitalCz\OpenIDConnect\Client\ClientCredentials;
use DigitalCz\OpenIDConnect\Client\JwtIdTokenValidator;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\DiscoveryConfig;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Config\StaticConfig;
use DigitalCz\OpenIDConnect\Discovery\CachingDiscoverer;
use DigitalCz\OpenIDConnect\Discovery\CachingJwksLoader;
use DigitalCz\OpenIDConnect\Discovery\HttpDiscoverer;
use DigitalCz\OpenIDConnect\Discovery\HttpJwksLoader;
use DigitalCz\OpenIDConnect\ResourceServer\CachingAccessTokenValidator;
use DigitalCz\OpenIDConnect\ResourceServer\JwtAccessTokenValidator;
use DigitalCz\OpenIDConnect\ResourceServer\OpaqueAccessTokenValidator;
use DigitalCz\OpenIDConnect\ResourceServer\ResourceServer;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Factory for creating configured OpenID Connect clients.
 */
final readonly class OidcFactory
{
    public function __construct(
        private HttpClientInterface $httpClient,
        private ?CacheInterface $cache = null,
    ) {
    }

    public function create(
        string|IssuerMetadata $issuerMetadata,
        ClientMetadata $clientMetadata,
    ): Oidc {
        if (is_string($issuerMetadata)) {
            $discoverer = new HttpDiscoverer($this->httpClient);

            if ($this->cache !== null) {
                $discoverer = new CachingDiscoverer($discoverer, $this->cache);
            }

            $config = new DiscoveryConfig($issuerMetadata, $discoverer, $clientMetadata);
        } else {
            $config = new StaticConfig($issuerMetadata, $clientMetadata);
        }

        $jwksLoader = new HttpJwksLoader($this->httpClient);

        if ($this->cache !== null) {
            $jwksLoader = new CachingJwksLoader($jwksLoader, $this->cache);
        }

        $idTokenValidator = new JwtIdTokenValidator($config, $jwksLoader);

        $authorizationCode = new AuthorizationCode($config, $this->httpClient, $idTokenValidator);

        $clientCredentials = new ClientCredentials($config, $this->httpClient);

        $opaqueAccessTokenValidator = new OpaqueAccessTokenValidator($config, $this->httpClient);

        if ($this->cache !== null) {
            $opaqueAccessTokenValidator = new CachingAccessTokenValidator($opaqueAccessTokenValidator, $this->cache);
        }

        $jwtAccessTokenValidator = new JwtAccessTokenValidator(
            $config,
            $jwksLoader,
            $clientMetadata->clientId(),
        );

        $resourceServer = new ResourceServer([
            $jwtAccessTokenValidator,
            $opaqueAccessTokenValidator,
        ]);

        return new Oidc($authorizationCode, $clientCredentials, $resourceServer);
    }
}
