<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use UnexpectedValueException;

#[CoversClass(JWT::class)]
class JWTTest extends TestCase
{
    public function testValidateWithValidJwt(): void
    {
        $validJwt = $this->createSampleJwt();

        $this->assertTrue(JWT::validate($validJwt));
    }

    #[DataProvider('invalidJwtProvider')]
    public function testValidateWithInvalidJwt(string $invalidJwt): void
    {
        $this->assertFalse(JWT::validate($invalidJwt));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidJwtProvider(): array
    {
        return [
            'empty string' => [''],
            'single part' => ['onlyonepart'],
            'two parts' => ['two.parts'],
            'four parts' => ['too.many.parts.here'],
            'invalid base64' => ['invalid@#$.header@#$.signature@#$'],
            'malformed header' => ['invalidheader.validpayload.validsignature'],
            'empty parts' => ['..'],
        ];
    }

    public function testParseWithValidJwt(): void
    {
        $payload = [
            'sub' => 'user123',
            'name' => 'John Doe',
            'iat' => time(),
        ];
        $jwt = $this->createSampleJwt($payload);

        $parsed = JWT::parse($jwt);

        $this->assertIsArray($parsed);
        $this->assertArrayHasKey('header', $parsed);
        $this->assertArrayHasKey('payload', $parsed);
        $this->assertArrayHasKey('signature', $parsed);

        // Check header structure
        $this->assertIsArray($parsed['header']);
        $this->assertSame('JWT', $parsed['header']['typ']);
        $this->assertSame('RS256', $parsed['header']['alg']);

        // Check payload contains our custom data
        $this->assertIsArray($parsed['payload']);
        $this->assertSame('user123', $parsed['payload']['sub']);
        $this->assertSame('John Doe', $parsed['payload']['name']);

        // Check signature is a string
        $this->assertIsString($parsed['signature']);
    }

    public function testParseWithInvalidJwt(): void
    {
        $this->expectException(UnexpectedValueException::class);
        JWT::parse($this->createInvalidJwt());
    }

    public function testParseWithMalformedParts(): void
    {
        $this->expectException(UnexpectedValueException::class);
        JWT::parse('invalid@#$.invalid@#$.invalid@#$');
    }

    public function testClaimsWithValidJwt(): void
    {
        $expectedClaims = [
            'sub' => 'user456',
            'name' => 'Jane Smith',
            'email' => 'jane@example.com',
            'roles' => ['admin', 'user'],
            'exp' => time() + 3600,
        ];

        $jwt = $this->createSampleJwt($expectedClaims);
        $claims = JWT::claims($jwt);

        $this->assertIsArray($claims);
        $this->assertSame('user456', $claims['sub']);
        $this->assertSame('Jane Smith', $claims['name']);
        $this->assertSame('jane@example.com', $claims['email']);
        $this->assertSame(['admin', 'user'], $claims['roles']);

        // Check that default claims from createSampleJwt are merged
        $this->assertSame('https://example.com', $claims['iss']);
        $this->assertSame('test-client-id', $claims['aud']);
    }

    public function testClaimsWithInvalidJwt(): void
    {
        $this->expectException(UnexpectedValueException::class);
        JWT::claims($this->createInvalidJwt());
    }

    public function testParseAndClaimsConsistency(): void
    {
        $jwt = $this->createSampleJwt(['custom' => 'value']);

        $parsed = JWT::parse($jwt);
        $claims = JWT::claims($jwt);

        // Claims should match the payload from parse
        $this->assertSame($parsed['payload'], $claims);
    }

    public function testWithRealWorldJwtStructure(): void
    {
        // Test with more realistic JWT structure
        $header = [
            'typ' => 'JWT',
            'alg' => 'RS256',
            'kid' => 'key-id-123',
        ];

        $payload = [
            'iss' => 'https://accounts.google.com',
            'aud' => 'client-id-here',
            'sub' => '1234567890',
            'exp' => time() + 3600,
            'iat' => time(),
            'auth_time' => time() - 10,
            'nonce' => 'random-nonce',
            'email' => 'user@example.com',
            'email_verified' => true,
            'name' => 'Test User',
            'picture' => 'https://example.com/avatar.jpg',
        ];

        $jwt = $this->createCustomJwt($header, $payload);

        $this->assertTrue(JWT::validate($jwt));

        $parsed = JWT::parse($jwt);
        $this->assertSame($header, $parsed['header']);
        $this->assertSame($payload, $parsed['payload']);
        $this->assertSame('fake-signature-for-testing', $parsed['signature']);

        $claims = JWT::claims($jwt);
        $this->assertSame($payload, $claims);
    }

    public function testValidateWithEmptyParts(): void
    {
        // Create JWT with empty payload
        $headerEncoded = Base64Url::encode('{"typ":"JWT","alg":"RS256"}');
        $payloadEncoded = ''; // Empty payload
        $signature = 'signature';

        $jwt = "{$headerEncoded}.{$payloadEncoded}.{$signature}";

        $this->assertFalse(JWT::validate($jwt));
    }

    public function testValidateWithInvalidJson(): void
    {
        // Create JWT with invalid JSON in header
        $headerEncoded = Base64Url::encode('{"typ":"JWT","alg":}'); // Invalid JSON
        $payloadEncoded = Base64Url::encode('{"sub":"123"}');
        $signature = 'signature';

        $jwt = "{$headerEncoded}.{$payloadEncoded}.{$signature}";

        $this->assertFalse(JWT::validate($jwt));
    }

    public function testLargeClaims(): void
    {
        // Test JWT with large payload
        $largeClaims = [
            'sub' => 'user123',
            'large_data' => str_repeat('data', 1000),
            'array_data' => array_fill(0, 100, 'item'),
            'nested' => [
                'level1' => [
                    'level2' => [
                        'level3' => 'deep value',
                    ],
                ],
            ],
        ];

        $jwt = $this->createSampleJwt($largeClaims);

        $this->assertTrue(JWT::validate($jwt));

        $claims = JWT::claims($jwt);
        $this->assertSame('user123', $claims['sub']);
        $this->assertStringContainsString('data', $claims['large_data']);
        $this->assertCount(100, $claims['array_data']);
        $this->assertSame('deep value', $claims['nested']['level1']['level2']['level3']);
    }

    public function testHeaderWithValidJwt(): void
    {
        $jwt = $this->createSampleJwt();

        $header = JWT::header($jwt);

        $this->assertIsArray($header);
        $this->assertSame('JWT', $header['typ']);
        $this->assertSame('RS256', $header['alg']);
    }

    public function testHeaderWithCustomHeader(): void
    {
        $customHeader = [
            'typ' => 'JWT',
            'alg' => 'ES256',
            'kid' => 'custom-key-id',
            'cty' => 'application/json',
        ];

        $jwt = $this->createCustomJwt($customHeader, ['sub' => 'test']);

        $header = JWT::header($jwt);

        $this->assertSame($customHeader, $header);
        $this->assertSame('ES256', $header['alg']);
        $this->assertSame('custom-key-id', $header['kid']);
        $this->assertSame('application/json', $header['cty']);
    }

    public function testHeaderWithInvalidJwt(): void
    {
        $this->expectException(UnexpectedValueException::class);
        JWT::header($this->createInvalidJwt());
    }

    public function testClaimWithExistingClaim(): void
    {
        $jwt = $this->createSampleJwt([
            'sub' => 'user789',
            'email' => 'test@example.com',
            'roles' => ['admin', 'user'],
            'custom_number' => 42,
            'custom_boolean' => true,
        ]);

        $this->assertSame('user789', JWT::claim($jwt, 'sub'));
        $this->assertSame('test@example.com', JWT::claim($jwt, 'email'));
        $this->assertSame(['admin', 'user'], JWT::claim($jwt, 'roles'));
        $this->assertSame(42, JWT::claim($jwt, 'custom_number'));
        $this->assertTrue(JWT::claim($jwt, 'custom_boolean'));
    }

    public function testClaimWithNonExistentClaim(): void
    {
        $jwt = $this->createSampleJwt(['sub' => 'user123']);

        $this->assertNull(JWT::claim($jwt, 'nonexistent'));
        $this->assertNull(JWT::claim($jwt, 'missing_claim'));
        $this->assertNull(JWT::claim($jwt, ''));
    }

    public function testClaimWithNullValue(): void
    {
        $jwt = $this->createSampleJwt([
            'sub' => 'user123',
            'null_claim' => null,
        ]);

        $this->assertNull(JWT::claim($jwt, 'null_claim'));
        $this->assertSame('user123', JWT::claim($jwt, 'sub'));
    }

    public function testClaimWithInvalidJwt(): void
    {
        $this->expectException(UnexpectedValueException::class);
        JWT::claim($this->createInvalidJwt(), 'sub');
    }

    public function testClaimWithComplexNestedData(): void
    {
        $nestedData = [
            'user_info' => [
                'profile' => [
                    'name' => 'John Doe',
                    'preferences' => [
                        'theme' => 'dark',
                        'language' => 'en',
                    ],
                ],
            ],
            'permissions' => [
                'read' => true,
                'write' => false,
                'admin' => true,
            ],
        ];

        $jwt = $this->createSampleJwt($nestedData);

        $userInfo = JWT::claim($jwt, 'user_info');
        $this->assertIsArray($userInfo);
        $this->assertSame('John Doe', $userInfo['profile']['name']);
        $this->assertSame('dark', $userInfo['profile']['preferences']['theme']);

        $permissions = JWT::claim($jwt, 'permissions');
        $this->assertIsArray($permissions);
        $this->assertTrue($permissions['read']);
        $this->assertFalse($permissions['write']);
        $this->assertTrue($permissions['admin']);
    }

    public function testHeaderAndClaimsConsistency(): void
    {
        $jwt = $this->createSampleJwt(['test' => 'value']);

        $parsed = JWT::parse($jwt);
        $header = JWT::header($jwt);
        $claims = JWT::claims($jwt);

        // Header should match the header from parse
        $this->assertSame($parsed['header'], $header);

        // Claims should match the payload from parse
        $this->assertSame($parsed['payload'], $claims);

        // Individual claim access should work
        $this->assertSame('value', JWT::claim($jwt, 'test'));
    }

    public function testAllMethodsWithSameJwt(): void
    {
        $testClaims = [
            'sub' => 'consistent-user',
            'iss' => 'test-issuer',
            'aud' => 'test-audience',
            'exp' => time() + 3600,
            'iat' => time(),
        ];

        $jwt = $this->createSampleJwt($testClaims);

        // Test all methods work with the same JWT
        $this->assertTrue(JWT::validate($jwt));

        $parsed = JWT::parse($jwt);
        $this->assertArrayHasKey('header', $parsed);
        $this->assertArrayHasKey('payload', $parsed);
        $this->assertArrayHasKey('signature', $parsed);

        $header = JWT::header($jwt);
        $this->assertSame('JWT', $header['typ']);

        $claims = JWT::claims($jwt);
        $this->assertSame('consistent-user', $claims['sub']);

        $subClaim = JWT::claim($jwt, 'sub');
        $this->assertSame('consistent-user', $subClaim);

        $missingClaim = JWT::claim($jwt, 'nonexistent');
        $this->assertNull($missingClaim);
    }
}
