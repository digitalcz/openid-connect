<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Discovery\Discoverer;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;

#[CoversClass(DiscoveryConfig::class)]
class DiscoveryConfigTest extends TestCase
{
    private Discoverer&MockObject $discoverer;
    private ClientMetadata $clientMetadata;
    private IssuerMetadata $issuerMetadata;
    private string $issuer;

    protected function setUp(): void
    {
        parent::setUp();

        $this->issuer = 'https://auth.example.com';
        $this->discoverer = $this->createMock(Discoverer::class);

        $this->issuerMetadata = new IssuerMetadata([
            'issuer' => $this->issuer,
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://auth.example.com/oauth/token',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
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

    public function testConstructor(): void
    {
        $config = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);

        $this->assertInstanceOf(DiscoveryConfig::class, $config);
        $this->assertInstanceOf(Config::class, $config);
    }

    public function testIssuerMetadata(): void
    {
        $this->discoverer->expects($this->once())
            ->method('discover')
            ->with($this->issuer)
            ->willReturn($this->issuerMetadata);

        $config = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);

        $result = $config->issuerMetadata();

        $this->assertSame($this->issuerMetadata, $result);
        $this->assertInstanceOf(IssuerMetadata::class, $result);
    }

    public function testClientMetadata(): void
    {
        $config = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);

        $result = $config->clientMetadata();

        $this->assertSame($this->clientMetadata, $result);
        $this->assertInstanceOf(ClientMetadata::class, $result);
    }

    public function testIssuerMetadataCallsDiscovererEachTime(): void
    {
        // Test that discoverer is called each time issuerMetadata() is called
        $this->discoverer->expects($this->exactly(2))
            ->method('discover')
            ->with($this->issuer)
            ->willReturn($this->issuerMetadata);

        $config = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);

        $result1 = $config->issuerMetadata();
        $result2 = $config->issuerMetadata();

        $this->assertSame($this->issuerMetadata, $result1);
        $this->assertSame($this->issuerMetadata, $result2);
    }

    public function testClientMetadataDoesNotCallDiscoverer(): void
    {
        $this->discoverer->expects($this->never())
            ->method('discover');

        $config = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);

        $result = $config->clientMetadata();

        $this->assertSame($this->clientMetadata, $result);
    }

    public function testWithDifferentIssuer(): void
    {
        $issuer2 = 'https://different-auth.example.com';
        $issuerMetadata2 = new IssuerMetadata([
            'issuer' => $issuer2,
            'authorization_endpoint' => 'https://different-auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://different-auth.example.com/oauth/token',
            'userinfo_endpoint' => 'https://different-auth.example.com/userinfo',
            'jwks_uri' => 'https://different-auth.example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);

        $this->discoverer->expects($this->exactly(2))
            ->method('discover')
            ->willReturnMap([
                [$this->issuer, $this->issuerMetadata],
                [$issuer2, $issuerMetadata2],
            ]);

        $config1 = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);
        $config2 = new DiscoveryConfig($issuer2, $this->discoverer, $this->clientMetadata);

        $issuer1Result = $config1->issuerMetadata();
        $issuer2Result = $config2->issuerMetadata();

        $this->assertSame($this->issuerMetadata, $issuer1Result);
        $this->assertSame($issuerMetadata2, $issuer2Result);
        $this->assertNotSame($issuer1Result, $issuer2Result);

        $this->assertSame($this->issuer, $issuer1Result->issuer());
        $this->assertSame($issuer2, $issuer2Result->issuer());
    }

    public function testReadonlyClassBehavior(): void
    {
        $config = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);

        // Verify the class maintains its state consistently
        $this->assertSame($this->clientMetadata, $config->clientMetadata());

        // Create second instance to verify independence
        $config2 = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);
        $this->assertNotSame($config, $config2);
        $this->assertSame($config->clientMetadata(), $config2->clientMetadata());
    }

    public function testDiscoveryConfigImplementsInterface(): void
    {
        $config = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);

        // Test that DiscoveryConfig properly implements the Config interface
        $this->assertInstanceOf(Config::class, $config);

        // Test interface methods exist and return correct types
        $this->assertInstanceOf(ClientMetadata::class, $config->clientMetadata());

        // Mock the discoverer for issuerMetadata test
        $this->discoverer->expects($this->once())
            ->method('discover')
            ->with($this->issuer)
            ->willReturn($this->issuerMetadata);

        $this->assertInstanceOf(IssuerMetadata::class, $config->issuerMetadata());
    }

    public function testDiscovererIsCalledWithCorrectIssuer(): void
    {
        $customIssuer = 'https://custom-issuer.example.com';

        $this->discoverer->expects($this->once())
            ->method('discover')
            ->with($customIssuer)
            ->willReturn($this->issuerMetadata);

        $config = new DiscoveryConfig($customIssuer, $this->discoverer, $this->clientMetadata);

        $config->issuerMetadata();
    }

    public function testWithDifferentClientMetadata(): void
    {
        $clientMetadata2 = new ClientMetadata(clientId: 'different-client-id');

        $config1 = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);
        $config2 = new DiscoveryConfig($this->issuer, $this->discoverer, $clientMetadata2);

        $this->assertNotSame($config1->clientMetadata(), $config2->clientMetadata());
        $this->assertSame('test-client-id', $config1->clientMetadata()->clientId());
        $this->assertSame('different-client-id', $config2->clientMetadata()->clientId());
    }

    public function testClientMetadataConsistency(): void
    {
        $config = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);

        // Multiple calls to clientMetadata should return the same instance
        $client1 = $config->clientMetadata();
        $client2 = $config->clientMetadata();

        $this->assertSame($client1, $client2);
        $this->assertSame($this->clientMetadata, $client1);
    }

    public function testDiscoveryIsNotCached(): void
    {
        // Test that discovery results are not cached within DiscoveryConfig
        // (caching should be handled by the Discoverer implementation itself)
        $issuerMetadata2 = new IssuerMetadata([
            'issuer' => $this->issuer,
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize/v2',
            'token_endpoint' => 'https://auth.example.com/oauth/token/v2',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo/v2',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json/v2',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);

        $this->discoverer->expects($this->exactly(2))
            ->method('discover')
            ->with($this->issuer)
            ->willReturnOnConsecutiveCalls($this->issuerMetadata, $issuerMetadata2);

        $config = new DiscoveryConfig($this->issuer, $this->discoverer, $this->clientMetadata);

        $result1 = $config->issuerMetadata();
        $result2 = $config->issuerMetadata();

        $this->assertSame($this->issuerMetadata, $result1);
        $this->assertSame($issuerMetadata2, $result2);
        $this->assertNotSame($result1, $result2);
    }
}
