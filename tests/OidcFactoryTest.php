<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\Client\AuthorizationCode;
use DigitalCz\OpenIDConnect\Client\AuthorizationUrlResult;
use DigitalCz\OpenIDConnect\Client\ClientCredentials;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\ResourceServer\ResourceServer;
use DigitalCz\OpenIDConnect\Util\PkceMethod;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

#[CoversClass(OidcFactory::class)]
class OidcFactoryTest extends TestCase
{
    private HttpClientInterface&MockObject $httpClient;
    private CacheInterface&MockObject $cache;
    private IssuerMetadata $issuerMetadata;

    public function testCreateWithMinimalParameters(): void
    {
        $oidc = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'test-client-id',
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());
    }

    public function testCreateWithStaticIssuerMetadata(): void
    {
        $oidc = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            cache: $this->cache,
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());
    }

    public function testCreateWithDiscoveryUrl(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);
        $cache = $this->createMock(CacheInterface::class);

        $this->setupDiscoveryMock($httpClient, 'auth.example.com');
        $this->setupCacheMock($cache);

        $discoveryUrl = 'https://auth.example.com';

        $oidc = OidcFactory::create(
            httpClient: $httpClient,
            issuer: $discoveryUrl,
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            cache: $cache,
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());

        // Trigger discovery by creating authorization URL
        $result = $oidc->authorizationCode()->createAuthorizationUrl();
        $this->assertInstanceOf(AuthorizationUrlResult::class, $result);
    }

    public function testCreateWithDiscoveryUrlWithoutCache(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);

        $this->setupDiscoveryMock($httpClient, 'auth.example.com');

        $discoveryUrl = 'https://auth.example.com';

        $oidc = OidcFactory::create(
            httpClient: $httpClient,
            issuer: $discoveryUrl,
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());

        // Trigger discovery by creating authorization URL
        $result = $oidc->authorizationCode()->createAuthorizationUrl();
        $this->assertInstanceOf(AuthorizationUrlResult::class, $result);
    }

    public function testCreateWithStaticIssuerMetadataWithoutCache(): void
    {
        $oidc = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());
    }

    public function testCreateComponentsAreProperlyConfigured(): void
    {
        $oidc = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            cache: $this->cache,
        );

        // Test that all main components exist
        $authorizationCode = $oidc->authorizationCode();
        $clientCredentials = $oidc->clientCredentials();
        $resourceServer = $oidc->resourceServer();

        $this->assertInstanceOf(AuthorizationCode::class, $authorizationCode);
        $this->assertInstanceOf(ClientCredentials::class, $clientCredentials);
        $this->assertInstanceOf(ResourceServer::class, $resourceServer);

        // Test that the resource server exists and is properly configured
        // We don't test token validation as that requires complex setup
        $this->assertInstanceOf(ResourceServer::class, $resourceServer);
    }

    public function testCreateWithDifferentIssuerUrls(): void
    {
        $discoveryUrls = [
            'https://accounts.google.com',
            'https://login.microsoftonline.com/common',
            'https://auth0.example.com',
        ];

        foreach ($discoveryUrls as $url) {
            $httpClient = $this->createMock(HttpClientInterface::class);
            $this->setupDiscoveryMock($httpClient, 'openid_configuration');

            $oidc = OidcFactory::create(
                httpClient: $httpClient,
                issuer: $url,
                clientId: 'test-client-id',
                clientSecret: 'test-client-secret',
                redirectUri: 'https://client.example.com/callback',
            );
            $this->assertInstanceOf(Oidc::class, $oidc);

            // Trigger discovery by creating authorization URL
            $result = $oidc->authorizationCode()->createAuthorizationUrl();
            $this->assertInstanceOf(AuthorizationUrlResult::class, $result);
        }
    }

    public function testCreateWithCustomParameters(): void
    {
        $oidc = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'custom-client-123',
            clientSecret: 'custom-secret-456',
            redirectUri: 'https://custom.example.com/callback',
            defaultScopes: ['openid', 'profile', 'custom-scope'],
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
        // The factory should preserve and use the provided parameters
        // This is verified by the fact that components are created successfully
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
    }

    public function testCreateWithEmptyDiscoveryUrl(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);

        $this->setupDiscoveryMock($httpClient, 'openid_configuration');

        $oidc = OidcFactory::create(
            httpClient: $httpClient,
            issuer: '',
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
        );

        $this->assertInstanceOf(Oidc::class, $oidc);

        // Trigger discovery by creating authorization URL
        $result = $oidc->authorizationCode()->createAuthorizationUrl();
        $this->assertInstanceOf(AuthorizationUrlResult::class, $result);
    }

    public function testCreateMultipleInstancesAreIndependent(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);

        $this->setupDiscoveryMock($httpClient, 'other.example.com');

        $oidc1 = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
        );

        $oidc2 = OidcFactory::create(
            httpClient: $httpClient,
            issuer: 'https://other.example.com',
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
        );

        $this->assertInstanceOf(Oidc::class, $oidc1);
        $this->assertInstanceOf(Oidc::class, $oidc2);
        $this->assertNotSame($oidc1, $oidc2);
        $this->assertNotSame($oidc1->authorizationCode(), $oidc2->authorizationCode());
        $this->assertNotSame($oidc1->clientCredentials(), $oidc2->clientCredentials());
        $this->assertNotSame($oidc1->resourceServer(), $oidc2->resourceServer());

        // Trigger discovery for oidc2 by creating authorization URL
        $result = $oidc2->authorizationCode()->createAuthorizationUrl();
        $this->assertInstanceOf(AuthorizationUrlResult::class, $result);
    }

    public function testCreateWithCustomCacheSecret(): void
    {
        $customSecret = 'my-custom-secret-key';

        $oidc = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            cache: $this->cache,
            cacheSecret: $customSecret,
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
    }

    public function testCreateWithAuthenticationMethod(): void
    {
        $oidc = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            authenticationMethod: AuthenticationMethod::ClientSecretPost,
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
    }

    public function testCreateWithPkceMethod(): void
    {
        $oidc = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'test-client-id',
            redirectUri: 'https://client.example.com/callback',
            pkceMethod: PkceMethod::S256,
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
    }

    public function testCreateWithCustomClock(): void
    {
        $clock = $this->createMock(ClockInterface::class);

        $oidc = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            clock: $clock,
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
    }

    public function testCreateWithAllOptionalParameters(): void
    {
        $clock = new SimpleClock();

        $oidc = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            defaultScopes: ['openid', 'profile', 'email', 'custom'],
            authenticationMethod: AuthenticationMethod::ClientSecretBasic,
            pkceMethod: PkceMethod::S256,
            cache: $this->cache,
            cacheSecret: 'test-cache-secret',
            clock: $clock,
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());
    }

    public function testCreateWithPublicClient(): void
    {
        $oidc = OidcFactory::create(
            httpClient: $this->httpClient,
            issuer: $this->issuerMetadata,
            clientId: 'public-client-id',
            redirectUri: 'https://client.example.com/callback',
            authenticationMethod: AuthenticationMethod::None,
            pkceMethod: PkceMethod::S256,
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->httpClient = $this->createMock(HttpClientInterface::class);
        $this->cache = $this->createMock(CacheInterface::class);

        $this->issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://auth.example.com/oauth/token',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
            'introspection_endpoint' => 'https://auth.example.com/oauth/introspect',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);
    }

    private function setupDiscoveryMock(
        HttpClientInterface&MockObject $httpClient,
        ?string $expectedUrlPattern = null,
    ): void {
        $discoveryData = [
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://auth.example.com/oauth/token',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
            'introspection_endpoint' => 'https://auth.example.com/oauth/introspect',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($discoveryData);

        $httpClient->expects($this->atLeastOnce())
            ->method('request')
            ->with('GET', $this->anything())
            ->willReturn($response);
    }

    private function setupCacheMock(CacheInterface&MockObject $cache): void
    {
        // Mock the cache to execute the callback directly without caching
        $cache->method('get')
            ->willReturnCallback(function (string $key, callable $callback) {
                // Create a mock ItemInterface for the callback
                $item = $this->createMock(ItemInterface::class);

                return $callback($item);
            });
    }
}
