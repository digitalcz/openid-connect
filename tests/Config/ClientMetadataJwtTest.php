<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\TestCase;
use DigitalCz\OpenIDConnect\Util\JWT;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ClientMetadata::class)]
class ClientMetadataJwtTest extends TestCase
{
    private const CLIENT_ID = 'test-client-id';
    private const CLIENT_SECRET = 'test-client-secret-that-is-long-enough-for-hmac-algorithms-minimum-256-bits';
    private const TOKEN_ENDPOINT = 'https://example.com/token';

    public function testClientSecretJwtAuthentication(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretJwt,
        );

        $options = $clientMetadata->applyCredentials([], self::TOKEN_ENDPOINT);

        $this->assertArrayHasKey('body', $options);
        $this->assertArrayHasKey('client_assertion_type', $options['body']);
        $this->assertArrayHasKey('client_assertion', $options['body']);

        $this->assertSame(
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            $options['body']['client_assertion_type'],
        );

        // Verify JWT structure
        $jwt = $options['body']['client_assertion'];
        $this->assertIsString($jwt);

        $parsed = JWT::parse($jwt);
        $header = $parsed['header'];
        $payload = $parsed['payload'];

        // Verify header
        $this->assertSame('HS256', $header['alg']);
        $this->assertSame('JWT', $header['typ']);

        // Verify payload
        $this->assertSame(self::CLIENT_ID, $payload['iss']);
        $this->assertSame(self::CLIENT_ID, $payload['sub']);
        $this->assertSame(self::TOKEN_ENDPOINT, $payload['aud']);
        $this->assertArrayHasKey('jti', $payload);
        $this->assertArrayHasKey('iat', $payload);
        $this->assertArrayHasKey('exp', $payload);
    }

    public function testPrivateKeyJwtAuthentication(): void
    {
        $privateKey = $this->generateRsaPrivateKey();

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            authenticationMethod: AuthenticationMethod::PrivateKeyJwt,
            privateKey: $privateKey,
        );

        $options = $clientMetadata->applyCredentials([], self::TOKEN_ENDPOINT);

        $this->assertArrayHasKey('body', $options);
        $this->assertArrayHasKey('client_assertion_type', $options['body']);
        $this->assertArrayHasKey('client_assertion', $options['body']);

        // Verify JWT structure
        $jwt = $options['body']['client_assertion'];
        $this->assertIsString($jwt);

        $parsed = JWT::parse($jwt);
        $header = $parsed['header'];
        $payload = $parsed['payload'];

        // Verify header
        $this->assertSame('RS256', $header['alg']);
        $this->assertSame('JWT', $header['typ']);

        // Verify payload
        $this->assertSame(self::CLIENT_ID, $payload['iss']);
        $this->assertSame(self::CLIENT_ID, $payload['sub']);
        $this->assertSame(self::TOKEN_ENDPOINT, $payload['aud']);
    }

    public function testPrivateKeyJwtWithJwk(): void
    {
        $privateKey = $this->generateRsaPrivateKey();
        $jwk = JWKFactory::createFromKey($privateKey, null, ['kid' => 'test-key-id']);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            authenticationMethod: AuthenticationMethod::PrivateKeyJwt,
            privateKeyJwk: $jwk,
        );

        $options = $clientMetadata->applyCredentials([], self::TOKEN_ENDPOINT);

        $jwt = $options['body']['client_assertion'];
        $parsed = JWT::parse($jwt);
        $header = $parsed['header'];

        $this->assertSame('test-key-id', $header['kid']);
    }

    public function testCustomSigningAlgorithm(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretJwt,
            tokenEndpointAuthSigningAlg: 'HS512',
        );

        $options = $clientMetadata->applyCredentials([], self::TOKEN_ENDPOINT);

        $jwt = $options['body']['client_assertion'];
        $parsed = JWT::parse($jwt);
        $header = $parsed['header'];

        $this->assertSame('HS512', $header['alg']);
    }

    public function testCustomClock(): void
    {
        $mockClock = new SimpleClock();
        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretJwt,
            clock: $mockClock,
        );

        $this->assertSame($mockClock, $clientMetadata->clock());
    }

    public function testJwtAuthenticationWithoutTokenEndpoint(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretJwt,
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Token endpoint URL is required for JWT authentication');

        $clientMetadata->applyCredentials([]);
    }

    public function testClientSecretJwtWithoutSecret(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            authenticationMethod: AuthenticationMethod::ClientSecretJwt,
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Client secret is required for client_secret_jwt authentication');

        $clientMetadata->applyCredentials([], self::TOKEN_ENDPOINT);
    }

    public function testPrivateKeyJwtWithoutKey(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            authenticationMethod: AuthenticationMethod::PrivateKeyJwt,
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Private key or JWK is required for private_key_jwt authentication');

        $clientMetadata->applyCredentials([], self::TOKEN_ENDPOINT);
    }

    public function testGetters(): void
    {
        $privateKey = $this->generateRsaPrivateKey();
        $jwk = JWKFactory::createFromKey($privateKey);
        $clock = new SimpleClock();

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            privateKey: $privateKey,
            privateKeyJwk: $jwk,
            jwksUri: 'https://example.com/jwks.json',
            tokenEndpointAuthSigningAlg: 'ES256',
            clock: $clock,
        );

        $this->assertSame($privateKey, $clientMetadata->privateKey());
        $this->assertSame($jwk, $clientMetadata->privateKeyJwk());
        $this->assertSame('https://example.com/jwks.json', $clientMetadata->jwksUri());
        $this->assertSame('ES256', $clientMetadata->tokenEndpointAuthSigningAlg());
        $this->assertSame($clock, $clientMetadata->clock());
    }

    public function testDefaultClock(): void
    {
        $clientMetadata = new ClientMetadata(clientId: self::CLIENT_ID);

        $this->assertInstanceOf(SimpleClock::class, $clientMetadata->clock());
    }

    public function testExistingBodyParametersArePreserved(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretJwt,
        );

        $initialOptions = [
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => 'test-code',
            ],
        ];

        $options = $clientMetadata->applyCredentials($initialOptions, self::TOKEN_ENDPOINT);

        $this->assertSame('authorization_code', $options['body']['grant_type']);
        $this->assertSame('test-code', $options['body']['code']);
        $this->assertArrayHasKey('client_assertion', $options['body']);
        $this->assertArrayHasKey('client_assertion_type', $options['body']);
    }

    private function generateRsaPrivateKey(): string
    {
        $keyResource = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($keyResource, $privateKey);

        return $privateKey;
    }
}
