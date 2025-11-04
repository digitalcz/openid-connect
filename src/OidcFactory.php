<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\BackChannelLogout\BackChannelLogoutHandler;
use DigitalCz\OpenIDConnect\BackChannelLogout\LogoutTokenValidator;
use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
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
use DigitalCz\OpenIDConnect\Util\PkceMethod;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use Jose\Component\Core\JWK;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Factory for creating configured OpenID Connect clients.
 */
final readonly class OidcFactory
{
    /**
     * @param string|array<string, string|string[]|bool>|IssuerMetadata $issuer
     * @param string|list<string> $defaultScopes
     */
    public static function create(
        HttpClientInterface $httpClient,
        string|array|IssuerMetadata $issuer,
        string $clientId,
        ?string $clientSecret = null,
        ?string $redirectUri = null,
        string|array $defaultScopes = ['openid', 'profile', 'email'],
        string|AuthenticationMethod $authenticationMethod = AuthenticationMethod::ClientSecretPost,
        string|PkceMethod $pkceMethod = PkceMethod::S256,
        ?CacheInterface $cache = null,
        ClockInterface $clock = new SimpleClock(),
        string $cacheSecret = 'default-oidc-cache-secret',
        ?string $privateKey = null,
        ?JWK $privateKeyJwk = null,
        ?string $tokenEndpointAuthSigningAlg = null,
        ?string $clientAssertionAudience = null,
        ?string $backchannelLogoutUri = null,
        bool $backchannelLogoutSessionRequired = false,
    ): Oidc {
        if (is_string($defaultScopes)) {
            $defaultScopes = explode(' ', $defaultScopes);
        }

        if (is_string($authenticationMethod)) {
            $authenticationMethod = AuthenticationMethod::from($authenticationMethod);
        }

        if (is_string($pkceMethod)) {
            $pkceMethod = PkceMethod::from($pkceMethod);
        }

        $clientMetadata = new ClientMetadata(
            clientId: $clientId,
            clientSecret: $clientSecret,
            redirectUri: $redirectUri,
            defaultScopes: $defaultScopes,
            authenticationMethod: $authenticationMethod,
            pkceMethod: $pkceMethod,
            privateKey: $privateKey,
            privateKeyJwk: $privateKeyJwk,
            tokenEndpointAuthSigningAlg: $tokenEndpointAuthSigningAlg,
            clientAssertionAudience: $clientAssertionAudience,
            clock: $clock,
            backchannelLogoutUri: $backchannelLogoutUri,
            backchannelLogoutSessionRequired: $backchannelLogoutSessionRequired,
        );

        if (is_string($issuer)) {
            $discoverer = new HttpDiscoverer($httpClient);

            if ($cache !== null) {
                $discoverer = new CachingDiscoverer($discoverer, $cache, CachingDiscoverer::DEFAULT_TTL, $cacheSecret);
            }

            $config = new DiscoveryConfig($issuer, $discoverer, $clientMetadata);
        } elseif (is_array($issuer)) {
            $config = new StaticConfig(new IssuerMetadata($issuer), $clientMetadata);
        } else {
            $config = new StaticConfig($issuer, $clientMetadata);
        }

        $jwksLoader = new HttpJwksLoader($httpClient);

        if ($cache !== null) {
            $jwksLoader = new CachingJwksLoader($jwksLoader, $cache, CachingJwksLoader::DEFAULT_TTL, $cacheSecret);
        }

        $idTokenValidator = new JwtIdTokenValidator($config, $jwksLoader, $clock);

        $authorizationCode = new AuthorizationCode($config, $httpClient, $idTokenValidator);

        $clientCredentials = new ClientCredentials($config, $httpClient);

        $opaqueAccessTokenValidator = new OpaqueAccessTokenValidator($config, $httpClient);

        if ($cache !== null) {
            $opaqueAccessTokenValidator = new CachingAccessTokenValidator(
                inner: $opaqueAccessTokenValidator,
                cache: $cache,
                clock: $clock,
                cacheSecret: $cacheSecret,
            );
        }

        $jwtAccessTokenValidator = new JwtAccessTokenValidator(
            $config,
            $jwksLoader,
            $clientMetadata->clientId(),
            $clock,
        );

        $resourceServer = new ResourceServer([
            $jwtAccessTokenValidator,
            $opaqueAccessTokenValidator,
        ]);

        $logoutTokenValidator = new LogoutTokenValidator($config, $jwksLoader, $clock);
        $backChannelLogoutHandler = new BackChannelLogoutHandler($logoutTokenValidator);

        return new Oidc($authorizationCode, $clientCredentials, $resourceServer, $backChannelLogoutHandler);
    }
}
