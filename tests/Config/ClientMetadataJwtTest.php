<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\TestCase;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use UnexpectedValueException;

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

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Claim "token_endpoint" is required and must be a string.');

        $clientMetadata->applyCredentials([]);
    }

    public function testPrivateKeyJwtAuthentication(): void
    {
        $privateKey = $this->generateRsaPrivateKey();

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            authenticationMethod: AuthenticationMethod::PrivateKeyJwt,
            privateKey: $privateKey,
        );

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Claim "token_endpoint" is required and must be a string.');

        $clientMetadata->applyCredentials([]);
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

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Claim "token_endpoint" is required and must be a string.');

        $clientMetadata->applyCredentials([]);
    }

    public function testCustomSigningAlgorithm(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretJwt,
            tokenEndpointAuthSigningAlg: 'HS512',
        );

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Claim "token_endpoint" is required and must be a string.');

        $clientMetadata->applyCredentials([]);
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

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Claim "token_endpoint" is required and must be a string.');

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

        $clientMetadata->applyCredentials([]);
    }

    public function testPrivateKeyJwtWithoutKey(): void
    {
        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            authenticationMethod: AuthenticationMethod::PrivateKeyJwt,
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Private key or JWK is required for private_key_jwt authentication');

        $clientMetadata->applyCredentials([]);
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

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Claim "token_endpoint" is required and must be a string.');

        $clientMetadata->applyCredentials($initialOptions);
    }

    private function generateRsaPrivateKey(): string
    {
        $keyResource = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($keyResource, $privateKey);
        openssl_pkey_free($keyResource);

        return $privateKey;
    }
}
