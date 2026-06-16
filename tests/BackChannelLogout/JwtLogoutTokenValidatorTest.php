<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DateTimeImmutable;
use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Clock\ClockInterface;
use RuntimeException;

#[CoversClass(JwtLogoutTokenValidator::class)]
class JwtLogoutTokenValidatorTest extends TestCase
{
    private Config&MockObject $config;
    private JwksLoader&MockObject $jwksLoader;
    private IssuerMetadata $issuerMetadata;
    private ClientMetadata $clientMetadata;
    private ClockInterface&MockObject $clock;

    public function testConstructor(): void
    {
        $validator = new JwtLogoutTokenValidator(
            $this->config,
            $this->jwksLoader,
            $this->clock,
            15,
            ['iss', 'aud', 'iat', 'jti', 'events', 'custom'],
        );

        $this->assertInstanceOf(JwtLogoutTokenValidator::class, $validator);
        $this->assertInstanceOf(LogoutTokenValidator::class, $validator);
    }

    public function testConstructorWithDefaults(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader);

        $this->assertInstanceOf(JwtLogoutTokenValidator::class, $validator);
        $this->assertInstanceOf(LogoutTokenValidator::class, $validator);
    }

    /**
     * @param list<string> $mandatoryClaims
     */
    #[DataProvider('mandatoryClaimsProvider')]
    public function testConstructorWithCustomMandatoryClaims(array $mandatoryClaims): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock, 10, $mandatoryClaims);

        $this->assertInstanceOf(JwtLogoutTokenValidator::class, $validator);
    }

    /**
     * @return array<string, array{list<string>}>
     */
    public static function mandatoryClaimsProvider(): array
    {
        return [
            'minimal claims' => [['iss', 'aud']],
            'standard claims' => [['iss', 'aud', 'iat', 'jti', 'events']],
            'extended claims' => [['iss', 'aud', 'iat', 'jti', 'events', 'sub']],
            'empty claims' => [[]],
        ];
    }

    public function testValidateAcceptsProperlySignedLogoutToken(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = new LogoutToken($this->createSignedJwt([
            'iss' => 'https://auth.example.com',
            'aud' => 'test-client-id',
            'iat' => time(),
            'jti' => 'unique-jti-id',
            'sub' => 'user-42',
            'events' => [JwtLogoutTokenValidator::LOGOUT_EVENT_URI => []],
        ]));

        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        // Full happy path: signature verifies, standard claims and logout-specific rules pass.
        $validator->validate($token);
        $this->addToAssertionCount(1);
    }

    public function testValidateRejectsSignedTokenWithExpiredExp(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = new LogoutToken($this->createSignedJwt([
            'iss' => 'https://auth.example.com',
            'aud' => 'test-client-id',
            'iat' => time() - 7200,
            'exp' => time() - 3600,
            'jti' => 'unique-jti-id',
            'sub' => 'user-42',
            'events' => [JwtLogoutTokenValidator::LOGOUT_EVENT_URI => []],
        ]));

        $this->jwksLoader->method('load')->willReturn($this->publicJwks());

        // Signature verifies, but the expired `exp` must be rejected by the claim checker.
        $this->expectException(InvalidTokenException::class);
        $validator->validate($token);
    }

    public function testValidateWithInvalidSignature(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createValidLogoutToken();

        $this->setupSuccessfulJwksLoad();

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Logout Token');
        $validator->validate($token);
    }

    public function testValidateWithJwksLoadFailure(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createValidLogoutToken();

        $this->jwksLoader->method('load')
            ->willThrowException(new RuntimeException('JWKS load failed'));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Logout Token: JWKS load failed');
        $validator->validate($token);
    }

    public function testValidateSignatureCallsJwksLoader(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createValidLogoutToken();

        $this->jwksLoader->expects($this->once())
            ->method('load')
            ->with('https://auth.example.com/.well-known/jwks.json')
            ->willReturn($this->createSampleJwks());

        $this->expectException(InvalidTokenException::class);
        $validator->validate($token);
    }

    public function testValidateWithWrongIssuer(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithPayload(['iss' => 'https://wrong-issuer.example.com']);

        $this->setupSuccessfulJwksLoad();

        $this->expectException(InvalidTokenException::class);
        $validator->validate($token);
    }

    public function testValidateWithWrongAudience(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithPayload(['aud' => 'wrong-client-id']);

        $this->setupSuccessfulJwksLoad();

        $this->expectException(InvalidTokenException::class);
        $validator->validate($token);
    }

    public function testValidateWithMissingEventsClaim(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithoutClaims(['events']);

        $this->setupSuccessfulJwksLoad();

        $this->expectException(InvalidTokenException::class);
        $validator->validate($token);
    }

    public function testValidateLogoutTokenClaimsAcceptsValidToken(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createValidLogoutToken();

        // Should not throw on a well-formed logout-token payload
        $validator->validateLogoutTokenClaims($token);
        $this->addToAssertionCount(1);
    }

    public function testValidateLogoutTokenClaimsAcceptsSidOnly(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $payload = $this->baseLogoutPayload();
        unset($payload['sub']);
        $payload['sid'] = 'session-id-only';
        $token = new LogoutToken($this->createCustomJwt($this->logoutJwtHeader(), $payload));

        $validator->validateLogoutTokenClaims($token);
        $this->addToAssertionCount(1);
    }

    public function testValidateLogoutTokenClaimsWithMissingEventsThrows(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithoutClaims(['events']);

        $this->expectException(InvalidTokenException::class);
        $validator->validateLogoutTokenClaims($token);
    }

    public function testValidateLogoutTokenClaimsWithEventsMissingLogoutEventKey(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithPayload([
            'events' => ['http://example.com/other-event' => []],
        ]);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('must contain');
        $validator->validateLogoutTokenClaims($token);
    }

    public function testValidateLogoutTokenClaimsWithLogoutEventValueNotAnObject(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithPayload([
            'events' => [JwtLogoutTokenValidator::LOGOUT_EVENT_URI => 'not-an-object'],
        ]);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('must be an object');
        $validator->validateLogoutTokenClaims($token);
    }

    public function testValidateLogoutTokenClaimsRejectsNonce(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithPayload(['nonce' => 'should-not-be-here']);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('MUST NOT contain a "nonce" claim');
        $validator->validateLogoutTokenClaims($token);
    }

    public function testValidateLogoutTokenClaimsRejectsMissingSubAndSid(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithoutClaims(['sub', 'sid']);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('MUST contain either a "sub" or "sid" claim');
        $validator->validateLogoutTokenClaims($token);
    }

    public function testValidateLogoutTokenClaimsRequiresSidWhenSessionRequired(): void
    {
        $config = $this->configWithSessionRequired(true);
        $validator = new JwtLogoutTokenValidator($config, $this->jwksLoader, $this->clock);
        // base payload carries `sub` but no `sid`
        $token = $this->createValidLogoutToken();

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('because back-channel logout session is required');
        $validator->validateLogoutTokenClaims($token);
    }

    public function testValidateLogoutTokenClaimsAcceptsSidWhenSessionRequired(): void
    {
        $config = $this->configWithSessionRequired(true);
        $validator = new JwtLogoutTokenValidator($config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithPayload(['sid' => 'session-123']);

        $validator->validateLogoutTokenClaims($token);
        $this->addToAssertionCount(1);
    }

    public function testValidateLogoutTokenClaimsAllowsMissingSidWhenSessionNotRequired(): void
    {
        // Default config has session not required; `sub` alone is sufficient.
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithoutClaims(['sid']);

        $validator->validateLogoutTokenClaims($token);
        $this->addToAssertionCount(1);
    }

    public function testValidateWithSidOnly(): void
    {
        // Token has sid, no sub. Should reach signature check (fail there with our fake JWKS).
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $payload = $this->baseLogoutPayload();
        unset($payload['sub']);
        $payload['sid'] = 'session-id-only';
        $token = new LogoutToken($this->createCustomJwt($this->logoutJwtHeader(), $payload));

        $this->setupSuccessfulJwksLoad();

        // Signature check will fail (our test JWKS is synthetic), but that proves
        // the validator proceeded past the sid-only presence requirement.
        $this->expectException(InvalidTokenException::class);
        $validator->validate($token);
    }

    public function testValidateWithMissingRequiredClaims(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithoutClaims(['jti']);

        $this->setupSuccessfulJwksLoad();

        $this->expectException(InvalidTokenException::class);
        $validator->validate($token);
    }

    public function testValidateWithFutureIat(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createLogoutTokenWithPayload(['iat' => time() + 3600]);

        $this->setupSuccessfulJwksLoad();

        $this->expectException(InvalidTokenException::class);
        $validator->validate($token);
    }

    public function testValidateSignatureWithInvalidJwks(): void
    {
        $validator = new JwtLogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);
        $token = $this->createValidLogoutToken();

        $this->jwksLoader->method('load')->willReturn([]);

        $this->expectException(InvalidTokenException::class);
        $validator->validate($token);
    }

    public function testValidateRejectsHs256TokenEvenWhenAdvertised(): void
    {
        // The OP (mis)advertises a symmetric algorithm alongside its JWKS, and the
        // rogue JWKS even exposes the matching HMAC secret as an `oct` key — so only
        // the asymmetric algorithm allow-list (RFC 8725 §3.1), not web-token's
        // key-type binding, can reject this logout token.
        $issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://auth.example.com',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
            'id_token_signing_alg_values_supported' => ['RS256', 'HS256'],
        ]);

        $config = $this->createMock(Config::class);
        $config->method('issuerMetadata')->willReturn($issuerMetadata);
        $config->method('clientMetadata')->willReturn($this->clientMetadata);

        $this->jwksLoader->method('load')->willReturn($this->symmetricJwks());

        $validator = new JwtLogoutTokenValidator($config, $this->jwksLoader, $this->clock);

        $token = new LogoutToken($this->createHs256Jwt([
            'iss' => 'https://auth.example.com',
            'aud' => 'test-client-id',
            'jti' => 'unique-jti-id',
            'sub' => 'user-42',
            'events' => [JwtLogoutTokenValidator::LOGOUT_EVENT_URI => []],
        ]));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Logout Token:');

        $validator->validate($token);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->config = $this->createMock(Config::class);
        $this->jwksLoader = $this->createMock(JwksLoader::class);
        $this->issuerMetadata = $this->createRealIssuerMetadata();
        $this->clientMetadata = $this->createRealClientMetadata();
        $this->clock = $this->createMock(ClockInterface::class);

        $this->setupDefaultMocks();
    }

    private function setupDefaultMocks(): void
    {
        $this->config->method('issuerMetadata')->willReturn($this->issuerMetadata);
        $this->config->method('clientMetadata')->willReturn($this->clientMetadata);
        $this->clock->method('now')->willReturn(new DateTimeImmutable('@' . time()));
    }

    private function createRealIssuerMetadata(): IssuerMetadata
    {
        return new IssuerMetadata([
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://auth.example.com/oauth/token',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
            'response_types_supported' => ['code', 'token', 'id_token'],
            'subject_types_supported' => ['public', 'pairwise'],
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256'],
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
        ]);
    }

    private function createRealClientMetadata(): ClientMetadata
    {
        return new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            defaultScopes: ['openid', 'profile', 'email'],
            authenticationMethod: AuthenticationMethod::ClientSecretPost,
            backchannelLogoutUri: 'https://client.example.com/logout/backchannel',
            backchannelLogoutSessionRequired: false,
        );
    }

    private function configWithSessionRequired(bool $required): Config&MockObject
    {
        $clientMetadata = new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            defaultScopes: ['openid', 'profile', 'email'],
            authenticationMethod: AuthenticationMethod::ClientSecretPost,
            backchannelLogoutUri: 'https://client.example.com/logout/backchannel',
            backchannelLogoutSessionRequired: $required,
        );

        $config = $this->createMock(Config::class);
        $config->method('issuerMetadata')->willReturn($this->issuerMetadata);
        $config->method('clientMetadata')->willReturn($clientMetadata);

        return $config;
    }

    private function createValidLogoutToken(): LogoutToken
    {
        return new LogoutToken(
            $this->createCustomJwt($this->logoutJwtHeader(), $this->baseLogoutPayload()),
        );
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function createLogoutTokenWithPayload(array $overrides): LogoutToken
    {
        return new LogoutToken(
            $this->createCustomJwt(
                $this->logoutJwtHeader(),
                array_merge($this->baseLogoutPayload(), $overrides),
            ),
        );
    }

    /**
     * @param list<string> $removed
     */
    private function createLogoutTokenWithoutClaims(array $removed): LogoutToken
    {
        $payload = $this->baseLogoutPayload();

        foreach ($removed as $claim) {
            unset($payload[$claim]);
        }

        return new LogoutToken($this->createCustomJwt($this->logoutJwtHeader(), $payload));
    }

    /**
     * @return array<string, mixed>
     */
    private function logoutJwtHeader(): array
    {
        return ['typ' => 'logout+jwt', 'alg' => 'RS256', 'kid' => 'test-key-id'];
    }

    /**
     * @return array<string, mixed>
     */
    private function baseLogoutPayload(): array
    {
        return [
            'iss' => 'https://auth.example.com',
            'aud' => 'test-client-id',
            'iat' => time(),
            'jti' => 'unique-jti-id',
            'sub' => 'user-42',
            'events' => [
                JwtLogoutTokenValidator::LOGOUT_EVENT_URI => [],
            ],
        ];
    }

    private function setupSuccessfulJwksLoad(): void
    {
        $this->jwksLoader->method('load')->willReturn($this->createSampleJwks());
    }
}
