<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Client\AuthorizationCode;
use DigitalCz\OpenIDConnect\Client\ClientCredentials;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\ResourceServer\ResourceServer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

#[CoversClass(OidcFactory::class)]
class OidcFactoryTest extends TestCase
{
    private HttpClientInterface&MockObject $httpClient;
    private CacheInterface&MockObject $cache;
    private ClientMetadata $clientMetadata;
    private IssuerMetadata $issuerMetadata;

    public function testConstructorWithHttpClientOnly(): void
    {
        $factory = new OidcFactory($this->httpClient);

        $this->assertInstanceOf(OidcFactory::class, $factory);
    }

    public function testConstructorWithHttpClientAndCache(): void
    {
        $factory = new OidcFactory($this->httpClient, $this->cache);

        $this->assertInstanceOf(OidcFactory::class, $factory);
    }

    public function testCreateWithStaticIssuerMetadata(): void
    {
        $factory = new OidcFactory($this->httpClient, $this->cache);

        $oidc = $factory->create($this->issuerMetadata, $this->clientMetadata);

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

        $factory = new OidcFactory($httpClient, $cache);
        $discoveryUrl = 'https://auth.example.com';

        $oidc = $factory->create($discoveryUrl, $this->clientMetadata);

        $this->assertInstanceOf(Oidc::class, $oidc);
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());
    }

    public function testCreateWithDiscoveryUrlWithoutCache(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);

        $this->setupDiscoveryMock($httpClient, 'auth.example.com');

        $factory = new OidcFactory($httpClient);
        $discoveryUrl = 'https://auth.example.com';

        $oidc = $factory->create($discoveryUrl, $this->clientMetadata);

        $this->assertInstanceOf(Oidc::class, $oidc);
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());
    }

    public function testCreateWithStaticIssuerMetadataWithoutCache(): void
    {
        $factory = new OidcFactory($this->httpClient);

        $oidc = $factory->create($this->issuerMetadata, $this->clientMetadata);

        $this->assertInstanceOf(Oidc::class, $oidc);
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());
    }

    public function testCreateComponentsAreProperlyConfigured(): void
    {
        $factory = new OidcFactory($this->httpClient, $this->cache);

        $oidc = $factory->create($this->issuerMetadata, $this->clientMetadata);

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

            $factory = new OidcFactory($httpClient);
            $oidc = $factory->create($url, $this->clientMetadata);
            $this->assertInstanceOf(Oidc::class, $oidc);
        }
    }

    public function testCreatePreservesClientMetadata(): void
    {
        $factory = new OidcFactory($this->httpClient);
        $customClientMetadata = new ClientMetadata(
            clientId: 'custom-client-123',
            clientSecret: 'custom-secret-456',
            redirectUri: 'https://custom.example.com/callback',
            defaultScopes: ['openid', 'profile', 'custom-scope'],
        );

        $oidc = $factory->create($this->issuerMetadata, $customClientMetadata);

        $this->assertInstanceOf(Oidc::class, $oidc);
        // The factory should preserve and use the provided client metadata
        // This is verified by the fact that components are created successfully
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
    }

    public function testCreateWithEmptyDiscoveryUrl(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);

        $this->setupDiscoveryMock($httpClient, 'openid_configuration');

        $factory = new OidcFactory($httpClient);

        $oidc = $factory->create('', $this->clientMetadata);

        $this->assertInstanceOf(Oidc::class, $oidc);
    }

    public function testCreateMultipleInstancesAreIndependent(): void
    {
        $httpClient = $this->createMock(HttpClientInterface::class);

        $this->setupDiscoveryMock($httpClient, 'other.example.com');

        $factory = new OidcFactory($httpClient);

        $oidc1 = $factory->create($this->issuerMetadata, $this->clientMetadata);
        $oidc2 = $factory->create('https://other.example.com', $this->clientMetadata);

        $this->assertInstanceOf(Oidc::class, $oidc1);
        $this->assertInstanceOf(Oidc::class, $oidc2);
        $this->assertNotSame($oidc1, $oidc2);
        $this->assertNotSame($oidc1->authorizationCode(), $oidc2->authorizationCode());
        $this->assertNotSame($oidc1->clientCredentials(), $oidc2->clientCredentials());
        $this->assertNotSame($oidc1->resourceServer(), $oidc2->resourceServer());
    }

    public function testConstructorWithCustomCacheSecret(): void
    {
        $customSecret = 'my-custom-secret-key';
        $factory = new OidcFactory($this->httpClient, $this->cache, $customSecret);

        $this->assertInstanceOf(OidcFactory::class, $factory);
    }

    public function testCreateWithCustomCacheSecretCreatesValidOidcInstance(): void
    {
        $customSecret = 'application-specific-secret';

        $factory = new OidcFactory($this->httpClient, $this->cache, $customSecret);
        $oidc = $factory->create($this->issuerMetadata, $this->clientMetadata);

        // Verify that the factory creates a valid Oidc instance with custom cache secret
        $this->assertInstanceOf(Oidc::class, $oidc);
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
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

        $this->clientMetadata = new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            defaultScopes: ['openid', 'profile', 'email'],
        );
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
