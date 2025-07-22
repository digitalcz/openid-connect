<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ClientMetadata::class)]
class ClientMetadataTest extends TestCase
{
    public function testConstructorWithMinimalParameters(): void
    {
        $clientMetadata = new ClientMetadata(clientId: 'test-client-id');

        $this->assertSame('test-client-id', $clientMetadata->clientId());
        $this->assertNull($clientMetadata->clientSecret());
        $this->assertNull($clientMetadata->redirectUri());
        $this->assertSame(['openid', 'profile', 'email'], $clientMetadata->defaultScopes());
        $this->assertSame(AuthenticationMethod::ClientSecretPost, $clientMetadata->authenticationMethod());
    }

    public function testConstructorWithAllParameters(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://example.com/callback',
            defaultScopes: ['openid', 'custom'],
            authenticationMethod: AuthenticationMethod::ClientSecretBasic,
        );

        $this->assertSame('test-client-id', $clientMetadata->clientId());
        $this->assertSame('test-client-secret', $clientMetadata->clientSecret());
        $this->assertSame('https://example.com/callback', $clientMetadata->redirectUri());
        $this->assertSame(['openid', 'custom'], $clientMetadata->defaultScopes());
        $this->assertSame(AuthenticationMethod::ClientSecretBasic, $clientMetadata->authenticationMethod());
    }

    public function testPublicClient(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: 'public-client-id',
            clientSecret: null,
            authenticationMethod: AuthenticationMethod::None,
        );

        $this->assertSame('public-client-id', $clientMetadata->clientId());
        $this->assertNull($clientMetadata->clientSecret());
        $this->assertSame(AuthenticationMethod::None, $clientMetadata->authenticationMethod());
    }

    public function testEmptyDefaultScopes(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: 'test-client-id',
            defaultScopes: [],
        );

        $this->assertSame([], $clientMetadata->defaultScopes());
    }

    public function testCustomScopes(): void
    {
        $customScopes = ['openid', 'profile', 'email', 'custom:read', 'custom:write'];
        $clientMetadata = new ClientMetadata(clientId: 'test-client-id', defaultScopes: $customScopes);

        $this->assertSame($customScopes, $clientMetadata->defaultScopes());
    }
}
