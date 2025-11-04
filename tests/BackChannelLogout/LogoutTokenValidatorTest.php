<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DateTimeImmutable;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\Exception\InvalidLogoutTokenException;
use DigitalCz\OpenIDConnect\Exception\UntrustedLogoutTokenException;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Clock\ClockInterface;

#[CoversClass(LogoutTokenValidator::class)]
class LogoutTokenValidatorTest extends TestCase
{
    private Config&MockObject $config;
    private JwksLoader&MockObject $jwksLoader;
    private IssuerMetadata $issuerMetadata;
    private ClientMetadata $clientMetadata;
    private ClockInterface&MockObject $clock;

    protected function setUp(): void
    {
        parent::setUp();

        $this->issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/authorize',
            'token_endpoint' => 'https://example.com/token',
            'jwks_uri' => 'https://example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);

        $this->clientMetadata = new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-secret',
        );

        $this->config = $this->createMock(Config::class);
        $this->config->method('issuerMetadata')->willReturn($this->issuerMetadata);
        $this->config->method('clientMetadata')->willReturn($this->clientMetadata);

        $this->jwksLoader = $this->createMock(JwksLoader::class);

        $this->clock = $this->createMock(ClockInterface::class);
        $this->clock->method('now')->willReturn(new DateTimeImmutable());
    }

    public function testConstructor(): void
    {
        $validator = new LogoutTokenValidator(
            $this->config,
            $this->jwksLoader,
            $this->clock,
            15,
            ['iss', 'aud', 'iat', 'jti', 'events', 'custom'],
        );

        $this->assertInstanceOf(LogoutTokenValidator::class, $validator);
    }

    public function testValidateWithInvalidFormat(): void
    {
        $validator = new LogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);

        $this->expectException(InvalidLogoutTokenException::class);
        $validator->validate('invalid-token');
    }

    public function testValidateWithNonceClaim(): void
    {
        $validator = new LogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);

        $token = $this->createSampleLogoutToken([
            'nonce' => 'should-not-be-here',
        ]);

        $this->setupSuccessfulJwksLoad();

        $this->expectException(InvalidLogoutTokenException::class);
        $this->expectExceptionMessage('must not contain a nonce claim');
        $validator->validate($token);
    }

    public function testValidateWithoutEventsLogoutEvent(): void
    {
        $validator = new LogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);

        $token = $this->createSampleLogoutToken([
            'events' => [
                'http://some.other.event' => [],
            ],
        ]);

        $this->setupSuccessfulJwksLoad();

        $this->expectException(InvalidLogoutTokenException::class);
        $this->expectExceptionMessage('must contain the logout event');
        $validator->validate($token);
    }

    public function testValidateWithoutSubOrSid(): void
    {
        $validator = new LogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);

        $payload = [
            'iss' => 'https://example.com',
            'aud' => 'test-client-id',
            'iat' => time(),
            'jti' => 'unique-id',
            'events' => [
                'http://schemas.openid.net/event/backchannel-logout' => [],
            ],
        ];
        $token = $this->createSampleJwt($payload);

        $this->setupSuccessfulJwksLoad();

        $this->expectException(InvalidLogoutTokenException::class);
        $this->expectExceptionMessage('must contain either sub or sid claim');
        $validator->validate($token);
    }

    public function testValidateWithSubOnly(): void
    {
        $validator = new LogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);

        $payload = [
            'iss' => 'https://example.com',
            'aud' => 'test-client-id',
            'iat' => time(),
            'jti' => 'unique-id',
            'events' => [
                'http://schemas.openid.net/event/backchannel-logout' => [],
            ],
            'sub' => 'user-123',
        ];
        $token = $this->createSampleJwt($payload);

        $this->setupSuccessfulJwksLoad();

        // Should not throw exception, but will fail on signature validation (mocked)
        $this->expectException(UntrustedLogoutTokenException::class);
        $validator->validate($token);
    }

    public function testValidateWithSidOnly(): void
    {
        $validator = new LogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);

        $payload = [
            'iss' => 'https://example.com',
            'aud' => 'test-client-id',
            'iat' => time(),
            'jti' => 'unique-id',
            'events' => [
                'http://schemas.openid.net/event/backchannel-logout' => [],
            ],
            'sid' => 'session-456',
        ];
        $token = $this->createSampleJwt($payload);

        $this->setupSuccessfulJwksLoad();

        // Should not throw exception, but will fail on signature validation (mocked)
        $this->expectException(UntrustedLogoutTokenException::class);
        $validator->validate($token);
    }

    public function testValidateWithBothSubAndSid(): void
    {
        $validator = new LogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);

        $token = $this->createSampleLogoutToken([
            'sub' => 'user-123',
            'sid' => 'session-456',
        ]);

        $this->setupSuccessfulJwksLoad();

        // Should not throw exception, but will fail on signature validation (mocked)
        $this->expectException(UntrustedLogoutTokenException::class);
        $validator->validate($token);
    }

    public function testValidateWithMissingRequiredClaim(): void
    {
        $validator = new LogoutTokenValidator($this->config, $this->jwksLoader, $this->clock);

        $payload = [
            'aud' => 'test-client-id',
            'iat' => time(),
            'jti' => 'unique-id',
            'events' => [
                'http://schemas.openid.net/event/backchannel-logout' => [],
            ],
            'sub' => 'user-123',
        ];
        $token = $this->createSampleJwt($payload);

        $this->setupSuccessfulJwksLoad();

        $this->expectException(InvalidLogoutTokenException::class);
        $validator->validate($token);
    }

    /**
     * Create a sample logout token for testing.
     *
     * @param array<string, mixed> $payload
     */
    private function createSampleLogoutToken(array $payload = []): string
    {
        $defaultPayload = [
            'iss' => 'https://example.com',
            'aud' => 'test-client-id',
            'iat' => time(),
            'jti' => 'unique-id-' . uniqid(),
            'events' => [
                'http://schemas.openid.net/event/backchannel-logout' => [],
            ],
            'sub' => 'user-123',
        ];

        $payload = array_merge($defaultPayload, $payload);

        return $this->createSampleJwt($payload);
    }

    private function setupSuccessfulJwksLoad(): void
    {
        $this->jwksLoader
            ->method('load')
            ->willReturn($this->createSampleJwks());
    }
}
