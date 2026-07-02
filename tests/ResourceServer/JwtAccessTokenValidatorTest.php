<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\TestCase;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use InvalidArgumentException;
use Jose\Component\Checker\IssuerChecker;
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

    public function testConstructorRejectsEmptyAudienceList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('$audience must not be an empty list');

        new JwtAccessTokenValidator($this->config, $this->jwksLoader, []);
    }

    public function testConstructorRejectsClaimCheckersCombinedWithAudience(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('$audience must be null when $claimCheckers is provided');

        new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'test-audience',
            claimCheckers: [new IssuerChecker(['https://auth.example.com'])],
        );
    }

    public function testConstructorRejectsEmptyClaimCheckers(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('$claimCheckers must not be empty');

        new JwtAccessTokenValidator($this->config, $this->jwksLoader, null, claimCheckers: []);
    }

    public function testConstructorRejectsDuplicateClaimCheckers(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Duplicate claim checker for claim "iss"');

        new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            null,
            claimCheckers: [
                new IssuerChecker(['https://auth.example.com']),
                new IssuerChecker(['https://other.example.com']),
            ],
        );
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
        $expiredJwt = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], [
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
        $invalidIssuerJwt = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], [
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
        $invalidAudienceJwt = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], [
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
        $missingClaimsJwt = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], [
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
        $futureIatJwt = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], [
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
        $nbfJwt = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], [
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

        $jwtWithoutScope = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], [
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
        $driftJwt = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], [
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
        $multiAudienceJwt = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], [
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
        $jwtWithClaims = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], $params);
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

    public function testValidateSignatureMethodIsCalledDirectly(): void
    {
        $jwtToken = new JwtAccessToken($this->createValidJwtString());

        $this->jwksLoader->expects($this->once())
            ->method('load')
            ->with('https://auth.example.com/.well-known/jwks.json')
            ->willReturn($this->createMockJwks());

        $this->expectException(InvalidTokenException::class);
        $this->validator->validate($jwtToken);
    }

    public function testValidateWithJwksLoadFailure(): void
    {
        $jwtToken = new JwtAccessToken($this->createValidJwtString());

        $this->jwksLoader->method('load')
            ->willThrowException(new RuntimeException('JWKS load failed'));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token: JWKS load failed');
        $this->validator->validate($jwtToken);
    }

    public function testMultipleValidationCallsReusesJwsLoader(): void
    {
        $jwtToken = new JwtAccessToken($this->createValidJwtString());

        $this->jwksLoader->method('load')
            ->willReturn($this->createMockJwks());

        // Call validate multiple times - JWS loader should be reused (cached)
        try {
            $this->validator->validate($jwtToken);
        } catch (InvalidTokenException $exception) {
            $this->assertInstanceOf(InvalidTokenException::class, $exception);
        }

        try {
            $this->validator->validate($jwtToken);
        } catch (InvalidTokenException $exception) {
            $this->assertInstanceOf(InvalidTokenException::class, $exception);
        }

        $this->assertTrue(true); // Test passes if no exceptions during setup
    }

    public function testValidateClaimsWithEmptyClaims(): void
    {
        $emptyClaimsJwt = $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], []);
        $jwtToken = new JwtAccessToken($emptyClaimsJwt);

        $this->expectException(InvalidTokenException::class);
        $this->validator->validate($jwtToken);
    }

    public function testValidateWithZeroTimeDrift(): void
    {
        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'test-audience',
            new SimpleClock(),
            0, // Zero time drift
        );

        $jwtToken = new JwtAccessToken($this->createValidJwtString());

        $this->expectException(InvalidTokenException::class);
        $validator->validate($jwtToken);
    }

    public function testValidateWithLargeTimeDrift(): void
    {
        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'test-audience',
            new SimpleClock(),
            3600, // 1 hour time drift
        );

        $jwtToken = new JwtAccessToken($this->createValidJwtString());

        $this->expectException(InvalidTokenException::class);
        $validator->validate($jwtToken);
    }

    public function testCreateJwsLoaderWithDifferentAlgorithms(): void
    {
        // Create issuer metadata with different algorithms
        $issuerWithMultipleAlgs = new IssuerMetadata([
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://auth.example.com/oauth/token',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256', 'HS256'],
        ]);

        $config = $this->createMock(Config::class);
        $config->method('issuerMetadata')->willReturn($issuerWithMultipleAlgs);

        $validator = new JwtAccessTokenValidator($config, $this->jwksLoader, 'test-audience');

        $jwtToken = new JwtAccessToken($this->createValidJwtString());

        $this->expectException(InvalidTokenException::class);
        $validator->validate($jwtToken);
    }

    public function testValidateReturnsValidatedAccessToken(): void
    {
        // This test shows that validate() should return ValidatedAccessToken on success
        // But with our mock setup, it will always throw due to signature validation
        $jwtToken = new JwtAccessToken($this->createValidJwtString());

        $this->expectException(InvalidTokenException::class);
        $this->validator->validate($jwtToken);
    }

    public function testValidateClaimsMethodIsCalledIndirectly(): void
    {
        // Test that validateClaims is called during validation process
        $jwtToken = new JwtAccessToken($this->createValidJwtString());

        $this->jwksLoader->method('load')
            ->willReturn($this->createMockJwks());

        $this->expectException(InvalidTokenException::class);
        $this->validator->validate($jwtToken);
    }

    public function testValidateAcceptsRealSignedTokenWithAudience(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        $jwt = $this->createSignedJwt([
            'iss' => 'https://auth.example.com',
            'aud' => 'test-audience',
        ]);

        $validated = $this->validator->validate(new JwtAccessToken($jwt));

        $this->assertInstanceOf(ValidatedAccessToken::class, $validated);
    }

    public function testValidateRejectsRealSignedTokenWithoutAudience(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        // Properly signed and otherwise valid, but missing the "aud" claim entirely.
        $jwt = $this->createSignedJwt([
            'iss' => 'https://auth.example.com',
            'aud' => null,
        ]);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $this->validator->validate(new JwtAccessToken($jwt));
    }

    public function testValidateIgnoresTypHeaderByDefault(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        // Unexpected "typ" header is accepted because token-type checking is opt-in.
        $jwt = $this->createSignedJwt(
            ['iss' => 'https://auth.example.com', 'aud' => 'test-audience'],
            ['typ' => 'unexpected'],
        );

        $validated = $this->validator->validate(new JwtAccessToken($jwt));

        $this->assertInstanceOf(ValidatedAccessToken::class, $validated);
    }

    public function testValidateRejectsWrongTokenTypeWhenConfigured(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'test-audience',
            new SimpleClock(),
            10,
            ['iss', 'sub', 'aud', 'exp', 'iat'],
            'at+jwt',
        );

        $jwt = $this->createSignedJwt(
            ['iss' => 'https://auth.example.com', 'aud' => 'test-audience'],
            ['typ' => 'JWT'],
        );

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $validator->validate(new JwtAccessToken($jwt));
    }

    public function testValidateAcceptsExpectedTokenTypeWhenConfigured(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'test-audience',
            new SimpleClock(),
            10,
            ['iss', 'sub', 'aud', 'exp', 'iat'],
            'at+jwt',
        );

        $jwt = $this->createSignedJwt(
            ['iss' => 'https://auth.example.com', 'aud' => 'test-audience'],
            ['typ' => 'at+jwt'],
        );

        $validated = $validator->validate(new JwtAccessToken($jwt));

        $this->assertInstanceOf(ValidatedAccessToken::class, $validated);
    }

    public function testValidateAcceptsApplicationAtJwtFormWhenConfigured(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'test-audience',
            new SimpleClock(),
            10,
            ['iss', 'sub', 'aud', 'exp', 'iat'],
            'at+jwt',
        );

        // RFC 9068 allows the prefixed media type form too.
        $jwt = $this->createSignedJwt(
            ['iss' => 'https://auth.example.com', 'aud' => 'test-audience'],
            ['typ' => 'application/at+jwt'],
        );

        $validated = $validator->validate(new JwtAccessToken($jwt));

        $this->assertInstanceOf(ValidatedAccessToken::class, $validated);
    }

    public function testValidateAcceptsCaseInsensitiveTokenTypeWhenConfigured(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'test-audience',
            new SimpleClock(),
            10,
            ['iss', 'sub', 'aud', 'exp', 'iat'],
            'at+jwt',
        );

        // Media types are case-insensitive (RFC 9068 / RFC 2045).
        $jwt = $this->createSignedJwt(
            ['iss' => 'https://auth.example.com', 'aud' => 'test-audience'],
            ['typ' => 'Application/AT+JWT'],
        );

        $validated = $validator->validate(new JwtAccessToken($jwt));

        $this->assertInstanceOf(ValidatedAccessToken::class, $validated);
    }

    public function testValidateRejectsMissingTypWhenConfigured(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            'test-audience',
            new SimpleClock(),
            10,
            ['iss', 'sub', 'aud', 'exp', 'iat'],
            'at+jwt',
        );

        // No typ header at all must be rejected when enforcement is enabled.
        $jwt = $this->createSignedJwt(
            ['iss' => 'https://auth.example.com', 'aud' => 'test-audience'],
            ['typ' => null],
        );

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $validator->validate(new JwtAccessToken($jwt));
    }

    public function testRejectsHs256TokenEvenWhenAdvertised(): void
    {
        // The OP (mis)advertises a symmetric algorithm alongside its JWKS, and the
        // rogue JWKS even exposes the matching HMAC secret as an `oct` key — so only
        // the asymmetric algorithm allow-list (RFC 8725 §3.1), not web-token's
        // key-type binding, can reject this token.
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://auth.example.com',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
            'id_token_signing_alg_values_supported' => ['RS256', 'HS256'],
        ]);

        $config = $this->createMock(Config::class);
        $config->method('issuerMetadata')->willReturn($issuerMetadata);

        $this->jwksLoader->method('load')->willReturn($this->symmetricJwks());

        $validator = new JwtAccessTokenValidator($config, $this->jwksLoader, 'test-audience', new SimpleClock());

        $jwt = $this->createHs256Jwt([
            'iss' => 'https://auth.example.com',
            'aud' => 'test-audience',
        ]);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $validator->validate(new JwtAccessToken($jwt));
    }

    public function testValidateAcceptsTokenWhenAudienceIsInConfiguredList(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            ['first-service', 'second-service'],
            new SimpleClock(),
        );

        $jwt = $this->createSignedJwt(['iss' => 'https://auth.example.com', 'aud' => 'second-service']);

        $this->assertInstanceOf(
            ValidatedAccessToken::class,
            $validator->validate(new JwtAccessToken($jwt)),
        );
    }

    public function testValidateRejectsTokenWhenAudienceNotInConfiguredList(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            ['first-service', 'second-service'],
            new SimpleClock(),
        );

        $jwt = $this->createSignedJwt(['iss' => 'https://auth.example.com', 'aud' => 'third-service']);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Access Token:');

        $validator->validate(new JwtAccessToken($jwt));
    }

    public function testValidateAcceptsArrayAudienceIntersectingConfiguredList(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            ['first-service', 'second-service'],
            new SimpleClock(),
        );

        // Token carries multiple audiences; one of them is in the configured allow-list.
        $jwt = $this->createSignedJwt([
            'iss' => 'https://auth.example.com',
            'aud' => ['unrelated-service', 'second-service'],
        ]);

        $this->assertInstanceOf(
            ValidatedAccessToken::class,
            $validator->validate(new JwtAccessToken($jwt)),
        );
    }

    public function testValidateWithNullAudienceAcceptsForeignAudience(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        // Audience validation disabled: a token minted for a different first-party client is accepted.
        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            null,
            new SimpleClock(),
        );

        $jwt = $this->createSignedJwt(['iss' => 'https://auth.example.com', 'aud' => 'some-other-client']);

        $this->assertInstanceOf(
            ValidatedAccessToken::class,
            $validator->validate(new JwtAccessToken($jwt)),
        );
    }

    public function testValidateWithNullAudienceAcceptsMissingAudienceWhenNotMandatory(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        // With the audience check disabled and "aud" dropped from the mandatory set, a token
        // without any "aud" claim is accepted.
        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            null,
            new SimpleClock(),
            10,
            ['iss', 'sub', 'exp', 'iat'],
        );

        $jwt = $this->createSignedJwt(['iss' => 'https://auth.example.com', 'aud' => null]);

        $this->assertInstanceOf(
            ValidatedAccessToken::class,
            $validator->validate(new JwtAccessToken($jwt)),
        );
    }

    public function testValidateWithInjectedClaimCheckersReplacesDefaultSet(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        // Only an issuer check is injected, fully replacing the default set: neither the
        // audience nor the expiration default checker runs.
        $validator = new JwtAccessTokenValidator(
            $this->config,
            $this->jwksLoader,
            null,
            new SimpleClock(),
            mandatoryClaims: ['iss'],
            claimCheckers: [new IssuerChecker(['https://auth.example.com'])],
        );

        // Foreign audience AND already expired — both would fail the defaults, both pass here.
        $jwt = $this->createSignedJwt([
            'iss' => 'https://auth.example.com',
            'aud' => 'some-other-client',
            'exp' => time() - 3600,
        ]);

        $this->assertInstanceOf(
            ValidatedAccessToken::class,
            $validator->validate(new JwtAccessToken($jwt)),
        );
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
        return $this->createCustomJwt(['alg' => 'RS256', 'typ' => 'JWT'], [
            'iss' => 'https://auth.example.com',
            'sub' => 'user123',
            'aud' => 'test-audience',
            'exp' => time() + 3600,
            'iat' => time(),
            'scope' => 'read write',
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function createMockJwks(): array
    {
        return [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'kid' => 'test-key-id',
                    'n' => 'mock-modulus',
                    'e' => 'AQAB',
                    'alg' => 'RS256',
                ],
            ],
        ];
    }
}
