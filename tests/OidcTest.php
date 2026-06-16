<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\BackChannelLogout\BackChannelLogoutHandler;
use DigitalCz\OpenIDConnect\BackChannelLogout\JwtLogoutTokenValidator;
use DigitalCz\OpenIDConnect\Client\AuthorizationCode;
use DigitalCz\OpenIDConnect\Client\ClientCredentials;
use DigitalCz\OpenIDConnect\Client\DeviceAuthorization;
use DigitalCz\OpenIDConnect\Client\JwtIdTokenValidator;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\ResourceServer\JwtAccessTokenValidator;
use DigitalCz\OpenIDConnect\ResourceServer\OpaqueAccessTokenValidator;
use DigitalCz\OpenIDConnect\ResourceServer\ResourceServer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[CoversClass(Oidc::class)]
class OidcTest extends TestCase
{
    private AuthorizationCode $authorizationCode;
    private ClientCredentials $clientCredentials;
    private DeviceAuthorization $deviceAuthorization;
    private ResourceServer $resourceServer;
    private BackChannelLogoutHandler $backChannelLogout;
    private Config&MockObject $config;
    private HttpClientInterface $httpClient;
    private IssuerMetadata $issuerMetadata;
    private ClientMetadata $clientMetadata;

    public function testConstructor(): void
    {
        $oidc = new Oidc(
            $this->authorizationCode,
            $this->clientCredentials,
            $this->deviceAuthorization,
            $this->resourceServer,
            $this->backChannelLogout,
        );

        $this->assertInstanceOf(Oidc::class, $oidc);
    }

    public function testAuthorizationCode(): void
    {
        $oidc = new Oidc(
            $this->authorizationCode,
            $this->clientCredentials,
            $this->deviceAuthorization,
            $this->resourceServer,
            $this->backChannelLogout,
        );

        $result = $oidc->authorizationCode();

        $this->assertSame($this->authorizationCode, $result);
        $this->assertInstanceOf(AuthorizationCode::class, $result);
    }

    public function testClientCredentials(): void
    {
        $oidc = new Oidc(
            $this->authorizationCode,
            $this->clientCredentials,
            $this->deviceAuthorization,
            $this->resourceServer,
            $this->backChannelLogout,
        );

        $result = $oidc->clientCredentials();

        $this->assertSame($this->clientCredentials, $result);
        $this->assertInstanceOf(ClientCredentials::class, $result);
    }

    public function testResourceServer(): void
    {
        $oidc = new Oidc(
            $this->authorizationCode,
            $this->clientCredentials,
            $this->deviceAuthorization,
            $this->resourceServer,
            $this->backChannelLogout,
        );

        $result = $oidc->resourceServer();

        $this->assertSame($this->resourceServer, $result);
        $this->assertInstanceOf(ResourceServer::class, $result);
    }

    public function testBackChannelLogout(): void
    {
        $oidc = new Oidc(
            $this->authorizationCode,
            $this->clientCredentials,
            $this->deviceAuthorization,
            $this->resourceServer,
            $this->backChannelLogout,
        );

        $result = $oidc->backChannelLogout();

        $this->assertSame($this->backChannelLogout, $result);
        $this->assertInstanceOf(BackChannelLogoutHandler::class, $result);
    }

    public function testDeviceAuthorization(): void
    {
        $oidc = new Oidc(
            $this->authorizationCode,
            $this->clientCredentials,
            $this->deviceAuthorization,
            $this->resourceServer,
            $this->backChannelLogout,
        );

        $result = $oidc->deviceAuthorization();

        $this->assertSame($this->deviceAuthorization, $result);
        $this->assertInstanceOf(DeviceAuthorization::class, $result);
    }

    public function testAllMethodsReturnSameInstancesConsistently(): void
    {
        $oidc = new Oidc(
            $this->authorizationCode,
            $this->clientCredentials,
            $this->deviceAuthorization,
            $this->resourceServer,
            $this->backChannelLogout,
        );

        // Test that multiple calls return the same instances
        $authCode1 = $oidc->authorizationCode();
        $authCode2 = $oidc->authorizationCode();
        $this->assertSame($authCode1, $authCode2);

        $clientCreds1 = $oidc->clientCredentials();
        $clientCreds2 = $oidc->clientCredentials();
        $this->assertSame($clientCreds1, $clientCreds2);

        $resourceServer1 = $oidc->resourceServer();
        $resourceServer2 = $oidc->resourceServer();
        $this->assertSame($resourceServer1, $resourceServer2);

        $backChannelLogout1 = $oidc->backChannelLogout();
        $backChannelLogout2 = $oidc->backChannelLogout();
        $this->assertSame($backChannelLogout1, $backChannelLogout2);
    }

    public function testReadonlyClassBehavior(): void
    {
        $oidc = new Oidc(
            $this->authorizationCode,
            $this->clientCredentials,
            $this->deviceAuthorization,
            $this->resourceServer,
            $this->backChannelLogout,
        );

        // Test that the class is readonly by verifying constructor injection works
        $this->assertSame($this->authorizationCode, $oidc->authorizationCode());
        $this->assertSame($this->clientCredentials, $oidc->clientCredentials());
        $this->assertSame($this->resourceServer, $oidc->resourceServer());
        $this->assertSame($this->backChannelLogout, $oidc->backChannelLogout());

        // The readonly class should maintain state consistently
        $oidc2 = new Oidc(
            $this->authorizationCode,
            $this->clientCredentials,
            $this->deviceAuthorization,
            $this->resourceServer,
            $this->backChannelLogout,
        );

        $this->assertSame($oidc->authorizationCode(), $oidc2->authorizationCode());
        $this->assertSame($oidc->clientCredentials(), $oidc2->clientCredentials());
        $this->assertSame($oidc->deviceAuthorization(), $oidc2->deviceAuthorization());
        $this->assertSame($oidc->resourceServer(), $oidc2->resourceServer());
        $this->assertSame($oidc->backChannelLogout(), $oidc2->backChannelLogout());
    }

    public function testFacadePattern(): void
    {
        // Test that Oidc acts as a proper facade providing access to all sub-components
        $oidc = new Oidc(
            $this->authorizationCode,
            $this->clientCredentials,
            $this->deviceAuthorization,
            $this->resourceServer,
            $this->backChannelLogout,
        );

        // Verify facade provides access to all main components
        $this->assertInstanceOf(AuthorizationCode::class, $oidc->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc->clientCredentials());
        $this->assertInstanceOf(ResourceServer::class, $oidc->resourceServer());
        $this->assertInstanceOf(BackChannelLogoutHandler::class, $oidc->backChannelLogout());

        // Verify each component is accessible and distinct
        $this->assertNotSame($oidc->authorizationCode(), $oidc->clientCredentials());
        $this->assertNotSame($oidc->authorizationCode(), $oidc->resourceServer());
        $this->assertNotSame($oidc->clientCredentials(), $oidc->resourceServer());
        $this->assertNotSame($oidc->backChannelLogout(), $oidc->resourceServer());
    }

    public function testWithDifferentImplementations(): void
    {
        // Create a second Oidc instance with different configuration to verify independence
        $config2 = $this->createMock(Config::class);
        $issuerMetadata2 = new IssuerMetadata([
            'issuer' => 'https://different-auth.example.com',
            'authorization_endpoint' => 'https://different-auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://different-auth.example.com/oauth/token',
            'userinfo_endpoint' => 'https://different-auth.example.com/userinfo',
            'jwks_uri' => 'https://different-auth.example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);
        $clientMetadata2 = new ClientMetadata(clientId: 'different-client-id');

        $config2->method('issuerMetadata')->willReturn($issuerMetadata2);
        $config2->method('clientMetadata')->willReturn($clientMetadata2);

        $jwksLoader2 = $this->createMock(JwksLoader::class);
        $jwksLoader2->method('load')->willReturn($this->createSampleJwks());

        $idTokenValidator2 = new JwtIdTokenValidator($config2, $jwksLoader2);
        $authCode2 = new AuthorizationCode($config2, $this->httpClient, $idTokenValidator2);
        $clientCreds2 = new ClientCredentials($config2, $this->httpClient);
        $deviceAuth2 = new DeviceAuthorization($config2, $this->httpClient);
        $resourceServer2 = new ResourceServer([]);
        $backChannelLogout2 = new BackChannelLogoutHandler(new JwtLogoutTokenValidator($config2, $jwksLoader2));

        $oidc1 = new Oidc(
            $this->authorizationCode,
            $this->clientCredentials,
            $this->deviceAuthorization,
            $this->resourceServer,
            $this->backChannelLogout,
        );
        $oidc2 = new Oidc($authCode2, $clientCreds2, $deviceAuth2, $resourceServer2, $backChannelLogout2);

        // Verify each Oidc instance maintains its own dependencies
        $this->assertNotSame($oidc1->authorizationCode(), $oidc2->authorizationCode());
        $this->assertNotSame($oidc1->clientCredentials(), $oidc2->clientCredentials());
        $this->assertNotSame($oidc1->deviceAuthorization(), $oidc2->deviceAuthorization());
        $this->assertNotSame($oidc1->resourceServer(), $oidc2->resourceServer());
        $this->assertNotSame($oidc1->backChannelLogout(), $oidc2->backChannelLogout());

        // Verify that the instances are properly typed
        $this->assertInstanceOf(AuthorizationCode::class, $oidc1->authorizationCode());
        $this->assertInstanceOf(AuthorizationCode::class, $oidc2->authorizationCode());
        $this->assertInstanceOf(ClientCredentials::class, $oidc1->clientCredentials());
        $this->assertInstanceOf(ClientCredentials::class, $oidc2->clientCredentials());
        $this->assertInstanceOf(ResourceServer::class, $oidc1->resourceServer());
        $this->assertInstanceOf(ResourceServer::class, $oidc2->resourceServer());
        $this->assertInstanceOf(BackChannelLogoutHandler::class, $oidc1->backChannelLogout());
        $this->assertInstanceOf(BackChannelLogoutHandler::class, $oidc2->backChannelLogout());
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->config = $this->createMock(Config::class);
        $this->httpClient = new MockHttpClient();
        $this->issuerMetadata = $this->createRealIssuerMetadata();
        $this->clientMetadata = $this->createRealClientMetadata();

        $this->setupDefaultMocks();
        $this->createRealObjects();
    }

    private function setupDefaultMocks(): void
    {
        $this->config->method('issuerMetadata')->willReturn($this->issuerMetadata);
        $this->config->method('clientMetadata')->willReturn($this->clientMetadata);
    }

    private function createRealObjects(): void
    {
        $jwksLoader = $this->createMock(JwksLoader::class);
        $jwksLoader->method('load')->willReturn($this->createSampleJwks());

        $idTokenValidator = new JwtIdTokenValidator($this->config, $jwksLoader);
        $this->authorizationCode = new AuthorizationCode($this->config, $this->httpClient, $idTokenValidator);

        $this->clientCredentials = new ClientCredentials($this->config, $this->httpClient);

        $this->deviceAuthorization = new DeviceAuthorization($this->config, $this->httpClient);

        $opaqueValidator = new OpaqueAccessTokenValidator($this->config, $this->httpClient);
        $jwtValidator = new JwtAccessTokenValidator($this->config, $jwksLoader, $this->clientMetadata->clientId());

        $this->resourceServer = new ResourceServer([$jwtValidator, $opaqueValidator]);

        $this->backChannelLogout = new BackChannelLogoutHandler(
            new JwtLogoutTokenValidator($this->config, $jwksLoader),
        );
    }

    private function createRealIssuerMetadata(): IssuerMetadata
    {
        return new IssuerMetadata([
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://auth.example.com/oauth/token',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);
    }

    private function createRealClientMetadata(): ClientMetadata
    {
        return new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            defaultScopes: ['openid', 'profile', 'email'],
        );
    }
}
