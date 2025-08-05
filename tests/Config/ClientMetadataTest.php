<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\TestCase;
use DigitalCz\OpenIDConnect\Util\PkceMethod;
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
        $this->assertSame(PkceMethod::S256, $clientMetadata->pkceMethod());
    }

    public function testConstructorWithAllParameters(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://example.com/callback',
            defaultScopes: ['openid', 'custom'],
            authenticationMethod: AuthenticationMethod::ClientSecretBasic,
            pkceMethod: PkceMethod::Plain,
        );

        $this->assertSame('test-client-id', $clientMetadata->clientId());
        $this->assertSame('test-client-secret', $clientMetadata->clientSecret());
        $this->assertSame('https://example.com/callback', $clientMetadata->redirectUri());
        $this->assertSame(['openid', 'custom'], $clientMetadata->defaultScopes());
        $this->assertSame(AuthenticationMethod::ClientSecretBasic, $clientMetadata->authenticationMethod());
        $this->assertSame(PkceMethod::Plain, $clientMetadata->pkceMethod());
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

    public function testPkceMethodS256(): void
    {
        $clientMetadata = new ClientMetadata(clientId: 'test-client-id', pkceMethod: PkceMethod::S256);

        $this->assertSame(PkceMethod::S256, $clientMetadata->pkceMethod());
    }

    public function testPkceMethodPlain(): void
    {
        $clientMetadata = new ClientMetadata(clientId: 'test-client-id', pkceMethod: PkceMethod::Plain);

        $this->assertSame(PkceMethod::Plain, $clientMetadata->pkceMethod());
    }

    public function testPkceMethodDisabled(): void
    {
        $clientMetadata = new ClientMetadata(clientId: 'test-client-id', pkceMethod: null);

        $this->assertNull($clientMetadata->pkceMethod());
    }

    public function testApplyCredentialsWithClientSecretPost(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            authenticationMethod: AuthenticationMethod::ClientSecretPost,
        );

        $options = ['body' => ['client_id' => 'overriding_client_id']];
        $result = $clientMetadata->applyCredentials($options);

        $expected = [
            'body' => [
                'client_id' => 'overriding_client_id',
                'client_secret' => 'test-client-secret',
            ],
        ];

        $this->assertSame($expected, $result);
    }

    public function testApplyCredentialsWithClientSecretBasic(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            authenticationMethod: AuthenticationMethod::ClientSecretBasic,
        );

        $options = ['auth_basic' => ['some_client_id', 'some_client_secret']];
        $result = $clientMetadata->applyCredentials($options);

        $expected = [
            'auth_basic' => ['some_client_id', 'some_client_secret'],
        ];

        $this->assertSame($expected, $result);
    }

    public function testApplyCredentialsWithNoneAuthentication(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: 'public-client-id',
            authenticationMethod: AuthenticationMethod::None,
        );

        $options = [];
        $result = $clientMetadata->applyCredentials($options);

        $expected = [
            'body' => [
                'client_id' => 'public-client-id',
            ],
        ];

        $this->assertSame($expected, $result);
    }

    public function testApplyCredentialsWithNoneAuthenticationPreservesExistingClientId(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: 'public-client-id',
            authenticationMethod: AuthenticationMethod::None,
        );

        $options = ['body' => ['client_id' => 'existing-client-id']];
        $result = $clientMetadata->applyCredentials($options);

        $expected = [
            'body' => [
                'client_id' => 'existing-client-id',
            ],
        ];

        $this->assertSame($expected, $result);
    }

    public function testApplyCredentialsWithEmptyOptions(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            authenticationMethod: AuthenticationMethod::ClientSecretPost,
        );

        $options = [];
        $result = $clientMetadata->applyCredentials($options);

        $expected = [
            'body' => [
                'client_id' => 'test-client-id',
                'client_secret' => 'test-client-secret',
            ],
        ];

        $this->assertSame($expected, $result);
    }

    public function testApplyCredentialsWithClientSecretBasicNullSecret(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: null,
            authenticationMethod: AuthenticationMethod::ClientSecretBasic,
        );

        $options = [];
        $result = $clientMetadata->applyCredentials($options);

        $expected = [
            'auth_basic' => ['test-client-id', ''],
        ];

        $this->assertSame($expected, $result);
    }
}
