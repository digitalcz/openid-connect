<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\TestCase;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Clock\ClockInterface;
use RuntimeException;

#[CoversClass(JwtAccessTokenValidator::class)]
class JwtAccessTokenValidatorTest extends TestCase
{
    private Config&MockObject $config;
    private JwksLoader&MockObject $jwksLoader;
    private IssuerMetadata $issuerMetadata;
    private JwtAccessTokenValidator $validator;

    public function testConstructor(): void
    {
        $validator = new JwtAccessTokenValidator($this->config, $this->jwksLoader, 'test-audience');

        $this->assertInstanceOf(JwtAccessTokenValidator::class, $validator);
    }

    public function testConstructorWithCustomParameters(): void
    {
        $customClock = $this->createMock(ClockInterface::class);
        $mandatoryClaims = ['iss', 'sub', 'exp', 'aud', 'scope'];

        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'custom-audience',
            $customClock,
            30,
            $mandatoryClaims,
        );

        $this->assertInstanceOf(JwtAccessTokenValidator::class, $validator);
    }

    public function testSupportsJwtAccessToken(): void
    {
        $jwtToken = new JwtAccessToken($this->createValidJwtString());

        $supports = $this->validator->supports($jwtToken);

        $this->assertTrue($supports);
    }

    public function testDoesNotSupportOpaqueAccessToken(): void
    {
        $opaqueToken = new OpaqueAccessToken('opaque-token-123');

        $supports = $this->validator->supports($opaqueToken);

        $this->assertFalse($supports);
    }

    public function testValidateFailsWithFakeJwt(): void
    {
        // Test that validation fails with fake JWT (as expected)
        $jwtToken = new JwtAccessToken($this->createValidJwtString());

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $this->validator->validate($jwtToken);
    }

    public function testValidateWithInvalidTokenType(): void
    {
        $opaqueToken = new OpaqueAccessToken('opaque-token-123');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Access token is not a JWT');

        $this->validator->validate($opaqueToken);
    }

    public function testValidateWithInvalidSignature(): void
    {
        $jwtToken = new JwtAccessToken($this->createValidJwtString());

        $this->config->method('issuerMetadata')->willReturn($this->issuerMetadata);

        // Mock JWKS loader to return empty key set to cause signature validation failure
        $this->jwksLoader->expects($this->once())
            ->method('load')
            ->with('https://auth.example.com/.well-known/jwks.json')
            ->willReturn([]);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $this->validator->validate($jwtToken);
    }

    public function testValidateWithExpiredToken(): void
    {
        $expiredTime = time() - 3600; // 1 hour ago
        $expiredJwt = $this->createJwtString([
            'iss' => 'https://auth.example.com',
            'sub' => 'user123',
            'aud' => 'test-audience',
            'exp' => $expiredTime,
            'iat' => $expiredTime - 100,
            'scope' => 'read write',
        ]);

        $jwtToken = new JwtAccessToken($expiredJwt);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $this->validator->validate($jwtToken);
    }

    public function testValidateWithInvalidIssuer(): void
    {
        $invalidIssuerJwt = $this->createJwtString([
            'iss' => 'https://wrong-issuer.example.com',
            'sub' => 'user123',
            'aud' => 'test-audience',
            'exp' => time() + 3600,
            'iat' => time(),
            'scope' => 'read write',
        ]);

        $jwtToken = new JwtAccessToken($invalidIssuerJwt);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $this->validator->validate($jwtToken);
    }

    public function testValidateWithInvalidAudience(): void
    {
        $invalidAudienceJwt = $this->createJwtString([
            'iss' => 'https://auth.example.com',
            'sub' => 'user123',
            'aud' => 'wrong-audience',
            'exp' => time() + 3600,
            'iat' => time(),
            'scope' => 'read write',
        ]);

        $jwtToken = new JwtAccessToken($invalidAudienceJwt);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $this->validator->validate($jwtToken);
    }

    public function testValidateWithMissingRequiredClaims(): void
    {
        $missingClaimsJwt = $this->createJwtString([
            'iss' => 'https://auth.example.com',
            'aud' => 'test-audience',
            'exp' => time() + 3600,
            // Missing 'sub' and 'iat' claims
        ]);

        $jwtToken = new JwtAccessToken($missingClaimsJwt);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $this->validator->validate($jwtToken);
    }

    public function testValidateWithFutureIssuedAt(): void
    {
        $futureTime = time() + 3600; // 1 hour in the future
        $futureIatJwt = $this->createJwtString([
            'iss' => 'https://auth.example.com',
            'sub' => 'user123',
            'aud' => 'test-audience',
            'exp' => $futureTime + 3600,
            'iat' => $futureTime,
            'scope' => 'read write',
        ]);

        $jwtToken = new JwtAccessToken($futureIatJwt);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $this->validator->validate($jwtToken);
    }

    public function testValidateWithNotBeforeClaim(): void
    {
        $nbfTime = time() + 3600; // Valid 1 hour from now
        $nbfJwt = $this->createJwtString([
            'iss' => 'https://auth.example.com',
            'sub' => 'user123',
            'aud' => 'test-audience',
            'exp' => time() + 7200,
            'iat' => time(),
            'nbf' => $nbfTime,
            'scope' => 'read write',
        ]);

        $jwtToken = new JwtAccessToken($nbfJwt);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $this->validator->validate($jwtToken);
    }

    public function testValidateWithCustomMandatoryClaims(): void
    {
        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'test-audience',
            new SimpleClock(),
            10,
            ['iss', 'sub', 'exp', 'iat', 'scope'], // Require scope claim
        );

        $jwtWithoutScope = $this->createJwtString([
            'iss' => 'https://auth.example.com',
            'sub' => 'user123',
            'aud' => 'test-audience',
            'exp' => time() + 3600,
            'iat' => time(),
            // Missing 'scope' claim
        ]);

        $jwtToken = new JwtAccessToken($jwtWithoutScope);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $validator->validate($jwtToken);
    }

    public function testValidateWithTimeDriftFails(): void
    {
        $almostExpiredTime = time() + 5; // Expires in 5 seconds
        $driftJwt = $this->createJwtString([
            'iss' => 'https://auth.example.com',
            'sub' => 'user123',
            'aud' => 'test-audience',
            'exp' => $almostExpiredTime,
            'iat' => time() - 5,
            'scope' => 'read write',
        ]);

        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'test-audience',
            new SimpleClock(),
            30, // Allow 30 seconds drift
        );

        $jwtToken = new JwtAccessToken($driftJwt);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $validator->validate($jwtToken);
    }

    public function testValidateWithArrayAudienceFails(): void
    {
        $multiAudienceJwt = $this->createJwtString([
            'iss' => 'https://auth.example.com',
            'sub' => 'user123',
            'aud' => ['test-audience', 'another-audience'],
            'exp' => time() + 3600,
            'iat' => time(),
            'scope' => 'read write',
        ]);

        $jwtToken = new JwtAccessToken($multiAudienceJwt);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $this->validator->validate($jwtToken);
    }

    /**
     * @param array<string, mixed> $params
     */
    #[DataProvider('validTokenClaimsProvider')]
    public function testValidateWithVariousValidClaimsAllFail(array $params): void
    {
        $jwtWithClaims = $this->createJwtString($params);
        $jwtToken = new JwtAccessToken($jwtWithClaims);

        // All these should fail due to signature validation with fake JWT
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $this->validator->validate($jwtToken);
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function validTokenClaimsProvider(): array
    {
        $baseTime = time();

        return [
            'with minimal required claims' => [
                [
                    'iss' => 'https://auth.example.com',
                    'sub' => 'user123',
                    'aud' => 'test-audience',
                    'exp' => $baseTime + 3600,
                    'iat' => $baseTime,
                ],
            ],
            'with scope claim' => [
                [
                    'iss' => 'https://auth.example.com',
                    'sub' => 'user123',
                    'aud' => 'test-audience',
                    'exp' => $baseTime + 3600,
                    'iat' => $baseTime,
                    'scope' => 'read write execute',
                ],
            ],
            'with custom claims' => [
                [
                    'iss' => 'https://auth.example.com',
                    'sub' => 'user123',
                    'aud' => 'test-audience',
                    'exp' => $baseTime + 3600,
                    'iat' => $baseTime,
                    'scope' => 'admin',
                    'client_id' => 'oauth-client-123',
                    'username' => 'john.doe',
                ],
            ],
            'with not-before claim' => [
                [
                    'iss' => 'https://auth.example.com',
                    'sub' => 'user123',
                    'aud' => 'test-audience',
                    'exp' => $baseTime + 3600,
                    'iat' => $baseTime,
                    'nbf' => $baseTime - 10, // Valid from 10 seconds ago
                    'scope' => 'read',
                ],
            ],
        ];
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->config = $this->createMock(Config::class);
        $this->jwksLoader = $this->createMock(JwksLoader::class);

        $this->issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://auth.example.com/oauth/token',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);

        $this->config->method('issuerMetadata')->willReturn($this->issuerMetadata);

        $this->validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'test-audience',
            new SimpleClock(),
        );
    }

    private function createValidJwtString(): string
    {
        return $this->createJwtString([
            'iss' => 'https://auth.example.com',
            'sub' => 'user123',
            'aud' => 'test-audience',
            'exp' => time() + 3600,
            'iat' => time(),
            'scope' => 'read write',
        ]);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function createJwtString(array $claims): string
    {
        $headerJson = json_encode(['alg' => 'RS256', 'typ' => 'JWT']);
        $payloadJson = json_encode($claims);

        if ($headerJson === false || $payloadJson === false) {
            throw new RuntimeException('Failed to encode JSON');
        }

        $header = base64_encode($headerJson);
        $payload = base64_encode($payloadJson);
        $signature = base64_encode('fake-signature');

        return $header . '.' . $payload . '.' . $signature;
    }
}
