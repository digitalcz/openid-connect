<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use stdClass;

#[CoversClass(RefreshToken::class)]
class RefreshTokenTest extends TestCase
{
    public function testConstructor(): void
    {
        $tokenString = 'refresh_token_abc123';
        $refreshToken = new RefreshToken($tokenString);

        $this->assertInstanceOf(RefreshToken::class, $refreshToken);
        $this->assertSame($tokenString, (string) $refreshToken);
    }

    public function testFromTokenResponseWithValidRefreshToken(): void
    {
        $responseData = [
            'access_token' => 'access_token_xyz',
            'refresh_token' => 'refresh_token_abc123',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ];

        $refreshToken = RefreshToken::tryFrom($responseData);

        $this->assertInstanceOf(RefreshToken::class, $refreshToken);
        $this->assertSame('refresh_token_abc123', (string) $refreshToken);
    }

    public function testFromTokenResponseWithoutRefreshToken(): void
    {
        $responseData = [
            'access_token' => 'access_token_xyz',
            'token_type' => 'Bearer',
        ];

        $refreshToken = RefreshToken::tryFrom($responseData);

        $this->assertNull($refreshToken);
    }

    /**
     * @param array<string, mixed> $responseData
     */
    #[DataProvider('invalidRefreshTokenProvider')]
    public function testFromTokenResponseWithInvalidRefreshToken(array $responseData): void
    {
        $refreshToken = RefreshToken::tryFrom($responseData);

        $this->assertNull($refreshToken);
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function invalidRefreshTokenProvider(): array
    {
        return [
            'null refresh token' => [
                ['refresh_token' => null, 'access_token' => 'token'],
            ],
            'integer refresh token' => [
                ['refresh_token' => 123, 'access_token' => 'token'],
            ],
            'boolean refresh token' => [
                ['refresh_token' => true, 'access_token' => 'token'],
            ],
            'array refresh token' => [
                ['refresh_token' => ['not', 'a', 'string'], 'access_token' => 'token'],
            ],
            'object refresh token' => [
                ['refresh_token' => new stdClass(), 'access_token' => 'token'],
            ],
        ];
    }

    public function testFromTokenResponseWithEmptyRefreshToken(): void
    {
        $responseData = [
            'refresh_token' => '',
            'access_token' => 'access_token_xyz',
        ];

        $refreshToken = RefreshToken::tryFrom($responseData);

        // Empty string should not create a valid token
        $this->assertNull($refreshToken);
    }

    public function testToString(): void
    {
        $tokenString = 'my_refresh_token_value';
        $refreshToken = new RefreshToken($tokenString);

        $this->assertSame($tokenString, (string) $refreshToken);
        $this->assertSame($tokenString, $refreshToken->__toString());
    }

    public function testWithLongRefreshToken(): void
    {
        // Test with a realistic long refresh token (JWT format)
        $longToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        $refreshToken = new RefreshToken($longToken);

        $this->assertSame($longToken, (string) $refreshToken);
    }

    public function testWithSpecialCharactersInToken(): void
    {
        // Test with token containing special characters (base64url encoding)
        $tokenWithSpecialChars = 'abc-123_def.456_ghi-789';

        $refreshToken = new RefreshToken($tokenWithSpecialChars);

        $this->assertSame($tokenWithSpecialChars, (string) $refreshToken);
    }

    public function testFromTokenResponseClientCredentialsFlow(): void
    {
        // Client Credentials flow typically doesn't include refresh_token
        $responseData = [
            'access_token' => 'access_token_xyz',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => 'api:read api:write',
        ];

        $refreshToken = RefreshToken::tryFrom($responseData);

        $this->assertNull($refreshToken);
    }

    public function testFromTokenResponseAuthorizationCodeFlow(): void
    {
        // Authorization Code flow typically includes refresh_token
        $responseData = [
            'access_token' => 'access_token_xyz',
            'refresh_token' => 'refresh_token_abc123',
            'id_token' => 'id_token_jwt',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => 'openid profile email',
        ];

        $refreshToken = RefreshToken::tryFrom($responseData);

        $this->assertInstanceOf(RefreshToken::class, $refreshToken);
        $this->assertSame('refresh_token_abc123', (string) $refreshToken);
    }

    public function testFromTokenResponseWithExtraFields(): void
    {
        // Test that extra fields in response don't affect refresh token extraction
        $responseData = [
            'access_token' => 'access_token_xyz',
            'refresh_token' => 'refresh_token_abc123',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => 'openid profile',
            'custom_field' => 'custom_value',
            'another_field' => 42,
        ];

        $refreshToken = RefreshToken::tryFrom($responseData);

        $this->assertInstanceOf(RefreshToken::class, $refreshToken);
        $this->assertSame('refresh_token_abc123', (string) $refreshToken);
    }

    public function testImmutability(): void
    {
        $tokenString = 'original_token';
        $refreshToken = new RefreshToken($tokenString);

        // Verify the token value cannot be changed (readonly property)
        $this->assertSame($tokenString, (string) $refreshToken);

        // Create another instance to verify they're independent
        $anotherToken = new RefreshToken('different_token');
        $this->assertSame('different_token', (string) $anotherToken);
        $this->assertSame($tokenString, (string) $refreshToken); // Original unchanged
    }
}
