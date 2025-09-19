<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\TestCase;
use DigitalCz\OpenIDConnect\Util\JWT;
use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use UnexpectedValueException;

#[CoversClass(ClientAuthenticator::class)]
class ClientAuthenticatorTest extends TestCase
{
    private const CLIENT_ID = 'test-client-id';
    private const CLIENT_SECRET = 'test-client-secret-that-is-long-enough-for-hmac-algorithms-minimum-256-bits';
    private const TOKEN_ENDPOINT = 'https://example.com/token';

    public function testClientSecretPostAuthentication(): void
    {
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretPost,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $options = $authenticator->applyAuthentication([]);

        $this->assertArrayHasKey('body', $options);
        $this->assertSame(self::CLIENT_ID, $options['body']['client_id']);
        $this->assertSame(self::CLIENT_SECRET, $options['body']['client_secret']);
    }

    public function testClientSecretBasicAuthentication(): void
    {
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretBasic,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $options = $authenticator->applyAuthentication([]);

        $this->assertArrayHasKey('auth_basic', $options);
        $this->assertSame([self::CLIENT_ID, self::CLIENT_SECRET], $options['auth_basic']);
    }

    public function testNoneAuthentication(): void
    {
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            authenticationMethod: AuthenticationMethod::None,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $options = $authenticator->applyAuthentication([]);

        $this->assertArrayHasKey('body', $options);
        $this->assertSame(self::CLIENT_ID, $options['body']['client_id']);
        $this->assertArrayNotHasKey('client_secret', $options['body']);
    }

    public function testClientSecretJwtAuthentication(): void
    {
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretJwt,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $options = $authenticator->applyAuthentication([]);

        $this->assertArrayHasKey('body', $options);
        $this->assertArrayHasKey('client_assertion_type', $options['body']);
        $this->assertArrayHasKey('client_assertion', $options['body']);

        $this->assertSame(
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            $options['body']['client_assertion_type'],
        );

        // Verify the JWT claims
        $jwt = $options['body']['client_assertion'];
        $payload = JWT::claims($jwt);

        $this->assertSame(self::CLIENT_ID, $payload['iss']);
        $this->assertSame(self::CLIENT_ID, $payload['sub']);
        $this->assertSame(self::TOKEN_ENDPOINT, $payload['aud']);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertArrayHasKey('iat', $payload);
        $this->assertArrayHasKey('jti', $payload);
    }

    public function testPrivateKeyJwtAuthenticationWithPrivateKey(): void
    {
        // Generate RSA private key for testing
        $keyResource = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        $this->assertNotFalse($keyResource, 'Failed to generate RSA key');

        $exported = openssl_pkey_export($keyResource, $privateKey);
        $this->assertTrue($exported, 'Failed to export private key');

        openssl_pkey_free($keyResource);

        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            authenticationMethod: AuthenticationMethod::PrivateKeyJwt,
            privateKey: $privateKey,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $options = $authenticator->applyAuthentication([]);

        $this->assertArrayHasKey('body', $options);
        $this->assertArrayHasKey('client_assertion_type', $options['body']);
        $this->assertArrayHasKey('client_assertion', $options['body']);

        $this->assertSame(
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            $options['body']['client_assertion_type'],
        );

        // Verify the JWT claims
        $jwt = $options['body']['client_assertion'];
        $payload = JWT::claims($jwt);

        $this->assertSame(self::CLIENT_ID, $payload['iss']);
        $this->assertSame(self::CLIENT_ID, $payload['sub']);
        $this->assertSame(self::TOKEN_ENDPOINT, $payload['aud']);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertArrayHasKey('iat', $payload);
        $this->assertArrayHasKey('jti', $payload);
    }

    public function testPrivateKeyJwtAuthenticationWithJwk(): void
    {
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            authenticationMethod: AuthenticationMethod::PrivateKeyJwt,
            privateKeyJwk: $jwk,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $options = $authenticator->applyAuthentication([]);

        $this->assertArrayHasKey('body', $options);
        $this->assertArrayHasKey('client_assertion_type', $options['body']);
        $this->assertArrayHasKey('client_assertion', $options['body']);

        $this->assertSame(
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            $options['body']['client_assertion_type'],
        );

        // Verify the JWT claims
        $jwt = $options['body']['client_assertion'];
        $payload = JWT::claims($jwt);

        $this->assertSame(self::CLIENT_ID, $payload['iss']);
        $this->assertSame(self::CLIENT_ID, $payload['sub']);
        $this->assertSame(self::TOKEN_ENDPOINT, $payload['aud']);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertArrayHasKey('iat', $payload);
        $this->assertArrayHasKey('jti', $payload);
    }

    public function testWithIssuerMetadataResolvesTokenEndpoint(): void
    {
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretPost,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $options = $authenticator->applyAuthentication([]);

        $this->assertArrayHasKey('body', $options);
        $this->assertSame(self::CLIENT_ID, $options['body']['client_id']);
        $this->assertSame(self::CLIENT_SECRET, $options['body']['client_secret']);
    }

    public function testWithCustomEndpointOverridesIssuerMetadata(): void
    {
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretPost,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $options = $authenticator->applyAuthentication([]);

        $this->assertArrayHasKey('body', $options);
        $this->assertSame(self::CLIENT_ID, $options['body']['client_id']);
        $this->assertSame(self::CLIENT_SECRET, $options['body']['client_secret']);
    }

    public function testThrowsExceptionForJwtAuthenticationWithoutEndpoint(): void
    {
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretJwt,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Claim "token_endpoint" is required and must be a string.');

        $authenticator->applyAuthentication([]);
    }

    public function testThrowsExceptionForClientSecretJwtWithoutSecret(): void
    {
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            authenticationMethod: AuthenticationMethod::ClientSecretJwt,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Client secret is required for client_secret_jwt authentication');

        $authenticator->applyAuthentication([]);
    }

    public function testThrowsExceptionForPrivateKeyJwtWithoutPrivateKey(): void
    {
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            authenticationMethod: AuthenticationMethod::PrivateKeyJwt,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Private key or JWK is required for private_key_jwt authentication');

        $authenticator->applyAuthentication([]);
    }

    public function testPreservesExistingOptionsValues(): void
    {
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'jwks_uri' => 'https://example.com/jwks',
        ]);

        $clientMetadata = new ClientMetadata(
            clientId: self::CLIENT_ID,
            clientSecret: self::CLIENT_SECRET,
            authenticationMethod: AuthenticationMethod::ClientSecretPost,
        );

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $initialOptions = [
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => 'test-code',
                'client_id' => 'different-client-id', // Should not be overridden
            ],
            'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
        ];

        $options = $authenticator->applyAuthentication($initialOptions);

        $this->assertArrayHasKey('body', $options);
        $this->assertSame('authorization_code', $options['body']['grant_type']);
        $this->assertSame('test-code', $options['body']['code']);
        $this->assertSame('different-client-id', $options['body']['client_id']); // Should not be overridden
        $this->assertSame(self::CLIENT_SECRET, $options['body']['client_secret']);
        $this->assertArrayHasKey('headers', $options);
        $this->assertSame('application/x-www-form-urlencoded', $options['headers']['Content-Type']);
    }
}
