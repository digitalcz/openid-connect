<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(StaticConfig::class)]
class StaticConfigTest extends TestCase
{
    private IssuerMetadata $issuerMetadata;
    private ClientMetadata $clientMetadata;

    public function testConstructor(): void
    {
        $config = new StaticConfig($this->issuerMetadata, $this->clientMetadata);

        $this->assertInstanceOf(StaticConfig::class, $config);
        $this->assertInstanceOf(Config::class, $config);
    }

    public function testIssuerMetadata(): void
    {
        $config = new StaticConfig($this->issuerMetadata, $this->clientMetadata);

        $result = $config->issuerMetadata();

        $this->assertSame($this->issuerMetadata, $result);
        $this->assertInstanceOf(IssuerMetadata::class, $result);
    }

    public function testClientMetadata(): void
    {
        $config = new StaticConfig($this->issuerMetadata, $this->clientMetadata);

        $result = $config->clientMetadata();

        $this->assertSame($this->clientMetadata, $result);
        $this->assertInstanceOf(ClientMetadata::class, $result);
    }

    public function testMultipleCallsReturnSameInstances(): void
    {
        $config = new StaticConfig($this->issuerMetadata, $this->clientMetadata);

        $issuer1 = $config->issuerMetadata();
        $issuer2 = $config->issuerMetadata();
        $this->assertSame($issuer1, $issuer2);

        $client1 = $config->clientMetadata();
        $client2 = $config->clientMetadata();
        $this->assertSame($client1, $client2);
    }

    public function testReadonlyClassBehavior(): void
    {
        $config = new StaticConfig($this->issuerMetadata, $this->clientMetadata);

        // Verify the class maintains its state consistently
        $this->assertSame($this->issuerMetadata, $config->issuerMetadata());
        $this->assertSame($this->clientMetadata, $config->clientMetadata());

        // Create second instance to verify independence
        $config2 = new StaticConfig($this->issuerMetadata, $this->clientMetadata);
        $this->assertNotSame($config, $config2);
        $this->assertSame($config->issuerMetadata(), $config2->issuerMetadata());
        $this->assertSame($config->clientMetadata(), $config2->clientMetadata());
    }

    public function testWithDifferentMetadata(): void
    {
        $issuer2 = new IssuerMetadata([
            'issuer' => 'https://different-auth.example.com',
            'authorization_endpoint' => 'https://different-auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://different-auth.example.com/oauth/token',
            'userinfo_endpoint' => 'https://different-auth.example.com/userinfo',
            'jwks_uri' => 'https://different-auth.example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);

        $client2 = new ClientMetadata(clientId: 'different-client-id');

        $config1 = new StaticConfig($this->issuerMetadata, $this->clientMetadata);
        $config2 = new StaticConfig($issuer2, $client2);

        $this->assertNotSame($config1->issuerMetadata(), $config2->issuerMetadata());
        $this->assertNotSame($config1->clientMetadata(), $config2->clientMetadata());

        $this->assertSame('https://auth.example.com', $config1->issuerMetadata()->issuer());
        $this->assertSame('https://different-auth.example.com', $config2->issuerMetadata()->issuer());

        $this->assertSame('test-client-id', $config1->clientMetadata()->clientId());
        $this->assertSame('different-client-id', $config2->clientMetadata()->clientId());
    }

    public function testStaticConfigureInterface(): void
    {
        $config = new StaticConfig($this->issuerMetadata, $this->clientMetadata);

        // Test that StaticConfig properly implements the Config interface
        $this->assertInstanceOf(Config::class, $config);

        // Test interface methods
        $issuerMetadata = $config->issuerMetadata();
        $clientMetadata = $config->clientMetadata();

        $this->assertInstanceOf(IssuerMetadata::class, $issuerMetadata);
        $this->assertInstanceOf(ClientMetadata::class, $clientMetadata);
    }

    public function testImmutability(): void
    {
        $config = new StaticConfig($this->issuerMetadata, $this->clientMetadata);

        // Test that the readonly class is immutable
        $issuer = $config->issuerMetadata();
        $client = $config->clientMetadata();

        // Multiple calls should return the exact same objects
        $this->assertSame($issuer, $config->issuerMetadata());
        $this->assertSame($client, $config->clientMetadata());

        // The objects should maintain their properties
        $this->assertSame('https://auth.example.com', $issuer->issuer());
        $this->assertSame('test-client-id', $client->clientId());
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://auth.example.com',
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
}
