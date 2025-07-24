<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(IdToken::class)]
class IdTokenTest extends TestCase
{
    public function testConstructor(): void
    {
        $jwtToken = $this->createSampleJwt();
        $idToken = new IdToken($jwtToken);

        $this->assertSame($jwtToken, (string) $idToken);
    }

    public function testFromTokenResponseWithValidIdToken(): void
    {
        $jwtToken = $this->createSampleJwt();
        $responseData = [
            'id_token' => $jwtToken,
            'access_token' => 'access-token',
        ];

        $idToken = IdToken::fromTokenResponse($responseData);

        $this->assertInstanceOf(IdToken::class, $idToken);
        $this->assertSame($jwtToken, (string) $idToken);
    }

    public function testFromTokenResponseWithoutIdToken(): void
    {
        $responseData = [
            'access_token' => 'access-token',
        ];

        $idToken = IdToken::fromTokenResponse($responseData);

        $this->assertNull($idToken);
    }

    public function testFromTokenResponseWithNullIdToken(): void
    {
        $responseData = [
            'id_token' => null,
            'access_token' => 'access-token',
        ];

        $idToken = IdToken::fromTokenResponse($responseData);

        $this->assertNull($idToken);
    }

    public function testFromTokenResponseWithInvalidIdTokenType(): void
    {
        $responseData = [
            'id_token' => 123, // Not a string
            'access_token' => 'access-token',
        ];

        $idToken = IdToken::fromTokenResponse($responseData);

        $this->assertNull($idToken);
    }

    public function testFromTokenResponseWithInvalidJwt(): void
    {
        $responseData = [
            'id_token' => 'invalid.jwt.format',
            'access_token' => 'access-token',
        ];

        $idToken = IdToken::fromTokenResponse($responseData);

        $this->assertNull($idToken);
    }

    public function testSubClaim(): void
    {
        $customPayload = [
            'sub' => 'user-12345',
        ];
        $jwtToken = $this->createSampleJwt($customPayload);
        $idToken = new IdToken($jwtToken);

        $this->assertSame('user-12345', $idToken->sub());
    }

    public function testNonceClaim(): void
    {
        $customPayload = [
            'nonce' => 'custom-nonce-value',
        ];
        $jwtToken = $this->createSampleJwt($customPayload);
        $idToken = new IdToken($jwtToken);

        $this->assertSame('custom-nonce-value', $idToken->nonce());
    }

    public function testClaims(): void
    {
        $customPayload = [
            'sub' => 'user-12345',
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'custom_claim' => 'custom_value',
        ];
        $jwtToken = $this->createSampleJwt($customPayload);
        $idToken = new IdToken($jwtToken);

        $claims = $idToken->claims();

        // Check that all custom claims are present
        $this->assertSame('user-12345', $claims['sub']);
        $this->assertSame('John Doe', $claims['name']);
        $this->assertSame('john@example.com', $claims['email']);
        $this->assertSame('custom_value', $claims['custom_claim']);

        // Check that default claims from createSampleJwt are also present
        $this->assertSame('https://example.com', $claims['iss']);
        $this->assertSame('test-client-id', $claims['aud']);
        $this->assertArrayHasKey('exp', $claims);
        $this->assertArrayHasKey('iat', $claims);
    }

    public function testAll(): void
    {
        $jwtToken = $this->createSampleJwt(['custom' => 'value']);
        $idToken = new IdToken($jwtToken);

        // all() should return the same as claims()
        $this->assertSame($idToken->claims(), $idToken->claims());
    }

    public function testToString(): void
    {
        $jwtToken = $this->createSampleJwt();
        $idToken = new IdToken($jwtToken);

        $this->assertSame($jwtToken, (string) $idToken);
        $this->assertSame($jwtToken, $idToken->__toString());
    }

    public function testClaimsTraitIntegration(): void
    {
        $customPayload = [
            'name' => 'John Doe',
            'age' => 30,
            'verified' => true,
            'roles' => ['admin', 'user'],
        ];
        $jwtToken = $this->createSampleJwt($customPayload);
        $idToken = new IdToken($jwtToken);

        // Test that ClaimsTrait methods work
        $this->assertTrue($idToken->has('name'));
        $this->assertFalse($idToken->has('nonexistent'));

        $this->assertSame('John Doe', $idToken->string('name'));
        $this->assertSame(30, $idToken->integer('age'));
        $this->assertTrue($idToken->boolean('verified'));
        $this->assertSame(['admin', 'user'], $idToken->strings('roles'));
    }

    public function testWithRealJwtStructure(): void
    {
        // Test with a more realistic JWT structure
        $payload = [
            'iss' => 'https://auth.example.com',
            'sub' => '1234567890',
            'aud' => 'my-client-id',
            'exp' => time() + 3600,
            'iat' => time(),
            'auth_time' => time() - 10,
            'nonce' => 'abc123nonce',
            'name' => 'Jane Smith',
            'email' => 'jane@example.com',
            'email_verified' => true,
            'picture' => 'https://example.com/avatar.jpg',
        ];

        $jwtToken = $this->createSampleJwt($payload);
        $idToken = new IdToken($jwtToken);

        $this->assertSame('1234567890', $idToken->sub());
        $this->assertSame('abc123nonce', $idToken->nonce());

        $claims = $idToken->claims();
        $this->assertSame('Jane Smith', $claims['name']);
        $this->assertSame('jane@example.com', $claims['email']);
        $this->assertTrue($claims['email_verified']);
        $this->assertSame('https://example.com/avatar.jpg', $claims['picture']);
    }
}
