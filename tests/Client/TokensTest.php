<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\ResourceServer\AccessToken;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Tokens::class)]
class TokensTest extends TestCase
{
    public function testConstructorWithMinimalParameters(): void
    {
        $tokens = new Tokens();

        $this->assertNull($tokens->accessToken());
        $this->assertNull($tokens->refreshToken());
        $this->assertNull($tokens->idToken());
        $this->assertNull($tokens->scope());
        $this->assertNull($tokens->tokenType());
        $this->assertNull($tokens->expiresIn());
    }

    public function testConstructorWithAllParameters(): void
    {
        $accessToken = AccessToken::tryFrom(['access_token' => 'test-access-token']);
        $refreshToken = RefreshToken::tryFrom(['refresh_token' => 'test-refresh-token']);
        $idToken = new IdToken($this->createSampleJwt());

        $tokens = new Tokens(
            accessToken: $accessToken,
            refreshToken: $refreshToken,
            idToken: $idToken,
            scope: 'openid profile email',
            tokenType: 'Bearer',
            expiresIn: 3600,
        );

        $this->assertSame($accessToken, $tokens->accessToken());
        $this->assertSame($refreshToken, $tokens->refreshToken());
        $this->assertSame($idToken, $tokens->idToken());
        $this->assertSame('openid profile email', $tokens->scope());
        $this->assertSame('Bearer', $tokens->tokenType());
        $this->assertSame(3600, $tokens->expiresIn());
    }

    public function testFromTokenResponseComplete(): void
    {
        $responseData = [
            'access_token' => 'test-access-token',
            'refresh_token' => 'test-refresh-token',
            'id_token' => $this->createSampleJwt(),
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => 'openid profile email',
        ];

        $tokens = Tokens::fromTokenResponse($responseData);

        $this->assertInstanceOf(AccessToken::class, $tokens->accessToken());
        $this->assertInstanceOf(RefreshToken::class, $tokens->refreshToken());
        $this->assertInstanceOf(IdToken::class, $tokens->idToken());
        $this->assertSame('Bearer', $tokens->tokenType());
        $this->assertSame(3600, $tokens->expiresIn());
        $this->assertSame('openid profile email', $tokens->scope());
    }

    public function testFromTokenResponseMinimal(): void
    {
        $responseData = [
            'access_token' => 'test-access-token',
        ];

        $tokens = Tokens::fromTokenResponse($responseData);

        $this->assertInstanceOf(AccessToken::class, $tokens->accessToken());
        $this->assertNull($tokens->refreshToken());
        $this->assertNull($tokens->idToken());
        $this->assertNull($tokens->tokenType());
        $this->assertNull($tokens->expiresIn());
        $this->assertNull($tokens->scope());
    }

    public function testFromTokenResponseWithInvalidTypes(): void
    {
        $responseData = [
            'access_token' => 'test-access-token',
            'token_type' => 123, // Invalid type - should be string
            'expires_in' => '3600', // Invalid type - should be int
            'scope' => ['openid', 'profile'], // Invalid type - should be string
        ];

        $tokens = Tokens::fromTokenResponse($responseData);

        $this->assertInstanceOf(AccessToken::class, $tokens->accessToken());
        $this->assertNull($tokens->tokenType()); // Should be null due to type mismatch
        $this->assertNull($tokens->expiresIn()); // Should be null due to type mismatch
        $this->assertNull($tokens->scope()); // Should be null due to type mismatch
    }

    public function testFromTokenResponseOnlyIdToken(): void
    {
        $responseData = [
            'id_token' => $this->createSampleJwt(),
        ];

        $tokens = Tokens::fromTokenResponse($responseData);

        $this->assertNull($tokens->accessToken());
        $this->assertNull($tokens->refreshToken());
        $this->assertInstanceOf(IdToken::class, $tokens->idToken());
        $this->assertNull($tokens->tokenType());
        $this->assertNull($tokens->expiresIn());
        $this->assertNull($tokens->scope());
    }

    public function testFromTokenResponseWithClientCredentialsFlow(): void
    {
        // Client Credentials flow typically doesn't include refresh_token or id_token
        $responseData = [
            'access_token' => 'test-access-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => 'api:read api:write',
        ];

        $tokens = Tokens::fromTokenResponse($responseData);

        $this->assertInstanceOf(AccessToken::class, $tokens->accessToken());
        $this->assertNull($tokens->refreshToken());
        $this->assertNull($tokens->idToken());
        $this->assertSame('Bearer', $tokens->tokenType());
        $this->assertSame(3600, $tokens->expiresIn());
        $this->assertSame('api:read api:write', $tokens->scope());
    }

    public function testFromTokenResponseWithInvalidIdToken(): void
    {
        $responseData = [
            'access_token' => 'test-access-token',
            'id_token' => 'invalid.jwt.token',
        ];

        $tokens = Tokens::fromTokenResponse($responseData);

        $this->assertInstanceOf(AccessToken::class, $tokens->accessToken());
        $this->assertNull($tokens->idToken()); // Should be null due to invalid JWT
    }
}
