<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use UnexpectedValueException;

#[CoversClass(JwtAccessToken::class)]
class JwtAccessTokenTest extends TestCase
{
    public function testConstructor(): void
    {
        $jwtToken = $this->createSampleJwt();
        $accessToken = new JwtAccessToken($jwtToken);

        $this->assertSame($jwtToken, (string) $accessToken);
    }

    public function testToString(): void
    {
        $jwtToken = $this->createSampleJwt();
        $accessToken = new JwtAccessToken($jwtToken);

        $this->assertSame($jwtToken, (string) $accessToken);
        $this->assertSame($jwtToken, $accessToken->__toString());
    }

    public function testClaims(): void
    {
        $customPayload = [
            'iss' => 'https://auth.example.com',
            'sub' => 'user-12345',
            'aud' => 'test-client',
            'exp' => time() + 3600,
            'iat' => time(),
            'jti' => 'jwt-id-123',
            'scope' => 'read write',
            'client_id' => 'my-client-id',
            'custom_claim' => 'custom_value',
        ];
        $jwtToken = $this->createSampleJwt($customPayload);
        $accessToken = new JwtAccessToken($jwtToken);

        $claims = $accessToken->claims();

        $this->assertSame('https://auth.example.com', $claims['iss']);
        $this->assertSame('user-12345', $claims['sub']);
        $this->assertSame('test-client', $claims['aud']);
        $this->assertSame('jwt-id-123', $claims['jti']);
        $this->assertSame('read write', $claims['scope']);
        $this->assertSame('my-client-id', $claims['client_id']);
        $this->assertSame('custom_value', $claims['custom_claim']);
        $this->assertArrayHasKey('exp', $claims);
        $this->assertArrayHasKey('iat', $claims);
    }

    public function testIssuerClaim(): void
    {
        $payload = ['iss' => 'https://auth.example.com'];
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        $this->assertSame('https://auth.example.com', $accessToken->iss());
    }

    public function testSubjectClaim(): void
    {
        $payload = ['sub' => 'user-67890'];
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        $this->assertSame('user-67890', $accessToken->sub());
    }

    public function testExpirationClaim(): void
    {
        $expTime = time() + 7200;
        $payload = ['exp' => $expTime];
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        $this->assertSame($expTime, $accessToken->exp());
    }

    public function testIssuedAtClaim(): void
    {
        $iatTime = time() - 300;
        $payload = ['iat' => $iatTime];
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        $this->assertSame($iatTime, $accessToken->iat());
    }

    public function testJwtIdClaim(): void
    {
        $payload = ['jti' => 'unique-jwt-identifier'];
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        $this->assertSame('unique-jwt-identifier', $accessToken->jti());
    }

    public function testNotBeforeClaim(): void
    {
        $nbfTime = time() - 600;
        $payload = ['nbf' => $nbfTime];
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        $this->assertSame($nbfTime, $accessToken->nbf());
    }

    public function testScopeClaim(): void
    {
        $payload = ['scope' => 'read:user write:user admin'];
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        $this->assertSame('read:user write:user admin', $accessToken->scope());
    }

    public function testClientIdClaim(): void
    {
        $payload = ['client_id' => 'oauth-client-123'];
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        $this->assertSame('oauth-client-123', $accessToken->clientId());
    }

    public function testAudienceClaimAsString(): void
    {
        $payload = ['aud' => 'single-audience'];
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        $this->assertSame('single-audience', $accessToken->aud());
    }

    public function testAudienceClaimAsArray(): void
    {
        $payload = ['aud' => ['audience1', 'audience2', 'audience3']];
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        $expected = ['audience1', 'audience2', 'audience3'];
        $this->assertSame($expected, $accessToken->aud());
    }

    public function testClaimsTraitIntegration(): void
    {
        $payload = [
            'string_claim' => 'test_string',
            'integer_claim' => 42,
            'boolean_claim' => true,
            'array_claim' => ['item1', 'item2', 'item3'],
        ];
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        // Test ClaimsTrait methods
        $this->assertTrue($accessToken->has('string_claim'));
        $this->assertFalse($accessToken->has('nonexistent_claim'));

        $this->assertSame('test_string', $accessToken->string('string_claim'));
        $this->assertSame(42, $accessToken->integer('integer_claim'));
        $this->assertTrue($accessToken->boolean('boolean_claim'));
        $this->assertSame(['item1', 'item2', 'item3'], $accessToken->strings('array_claim'));

        $this->assertSame('default_value', $accessToken->get('nonexistent', 'default_value'));
    }

    /**
     * @param array<string, mixed> $payload
     */
    #[DataProvider('invalidClaimTypeProvider')]
    public function testInvalidClaimTypes(string $method, array $payload, string $claim): void
    {
        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        $this->expectException(UnexpectedValueException::class);
        $accessToken->$method($claim);
    }

    #[DataProvider('missingClaimProvider')]
    public function testMissingRequiredClaims(string $method, string $claim): void
    {
        // Create JWT with empty payload to test missing claims
        $jwtToken = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], []);
        $accessToken = new JwtAccessToken($jwtToken);

        $this->expectException(UnexpectedValueException::class);
        $accessToken->$method($claim);
    }

    public function testWithComplexRealWorldJwtStructure(): void
    {
        $currentTime = time();
        $payload = [
            'iss' => 'https://oauth.example.com',
            'sub' => 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'aud' => ['api.example.com', 'admin.example.com'],
            'exp' => $currentTime + 3600,
            'iat' => $currentTime,
            'nbf' => $currentTime - 10,
            'jti' => '550e8400-e29b-41d4-a716-446655440000',
            'scope' => 'openid profile email admin:read admin:write',
            'client_id' => 'oauth2-client-production',
            'azp' => 'oauth2-client-production',
            'gty' => 'client_credentials',
            'permissions' => ['read:users', 'write:users', 'delete:users'],
            'roles' => ['admin', 'user'],
        ];

        $jwtToken = $this->createSampleJwt($payload);
        $accessToken = new JwtAccessToken($jwtToken);

        // Test all claim methods with realistic data
        $this->assertSame('https://oauth.example.com', $accessToken->iss());
        $this->assertSame('f47ac10b-58cc-4372-a567-0e02b2c3d479', $accessToken->sub());
        $this->assertSame(['api.example.com', 'admin.example.com'], $accessToken->aud());
        $this->assertSame($currentTime + 3600, $accessToken->exp());
        $this->assertSame($currentTime, $accessToken->iat());
        $this->assertSame($currentTime - 10, $accessToken->nbf());
        $this->assertSame('550e8400-e29b-41d4-a716-446655440000', $accessToken->jti());
        $this->assertSame('openid profile email admin:read admin:write', $accessToken->scope());
        $this->assertSame('oauth2-client-production', $accessToken->clientId());

        // Test that claims() returns all data
        $claims = $accessToken->claims();
        $this->assertSame('client_credentials', $claims['gty']);
        $this->assertSame(['read:users', 'write:users', 'delete:users'], $claims['permissions']);
        $this->assertSame(['admin', 'user'], $claims['roles']);
    }

    /**
     * @return array<string, array{string, array<string, mixed>, string}>
     */
    public static function invalidClaimTypeProvider(): array
    {
        return [
            'string method with integer' => ['string', ['claim' => 123], 'claim'],
            'string method with array' => ['string', ['claim' => ['array']], 'claim'],
            'string method with boolean' => ['string', ['claim' => true], 'claim'],
            'integer method with string' => ['integer', ['claim' => 'not-int'], 'claim'],
            'integer method with array' => ['integer', ['claim' => [1, 2, 3]], 'claim'],
            'boolean method with string' => ['boolean', ['claim' => 'not-bool'], 'claim'],
            'boolean method with integer' => ['boolean', ['claim' => 1], 'claim'],
        ];
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function missingClaimProvider(): array
    {
        return [
            'missing iss' => ['iss', 'iss'],
            'missing sub' => ['sub', 'sub'],
            'missing exp' => ['exp', 'exp'],
            'missing iat' => ['iat', 'iat'],
            'missing jti' => ['jti', 'jti'],
            'missing nbf' => ['nbf', 'nbf'],
            'missing scope' => ['scope', 'scope'],
            'missing client_id' => ['clientId', 'client_id'],
        ];
    }
}
