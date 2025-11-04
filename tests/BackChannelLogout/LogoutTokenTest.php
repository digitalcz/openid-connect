<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use UnexpectedValueException;

#[CoversClass(LogoutToken::class)]
class LogoutTokenTest extends TestCase
{
    public function testFromString(): void
    {
        $tokenString = $this->createSampleLogoutToken();
        $token = LogoutToken::from($tokenString);

        $this->assertInstanceOf(LogoutToken::class, $token);
        $this->assertSame($tokenString, (string) $token);
    }

    public function testFromInvalidString(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid JWT logout token format');

        LogoutToken::from('invalid-token');
    }

    public function testFromNonString(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Cannot create LogoutToken from array');

        LogoutToken::from(['not' => 'a string']);
    }

    public function testIssuer(): void
    {
        $token = LogoutToken::from($this->createSampleLogoutToken());

        $this->assertSame('https://example.com', $token->issuer());
    }

    public function testAudienceString(): void
    {
        $token = LogoutToken::from($this->createSampleLogoutToken());

        $this->assertSame('test-client-id', $token->audience());
    }

    public function testAudienceArray(): void
    {
        $tokenString = $this->createSampleLogoutToken([
            'aud' => ['client1', 'client2'],
        ]);
        $token = LogoutToken::from($tokenString);

        $audience = $token->audience();
        $this->assertIsArray($audience);
        $this->assertSame(['client1', 'client2'], $audience);
    }

    public function testSubject(): void
    {
        $token = LogoutToken::from($this->createSampleLogoutToken([
            'sub' => 'user-123',
        ]));

        $this->assertSame('user-123', $token->subject());
    }

    public function testSubjectNull(): void
    {
        $payload = [
            'iss' => 'https://example.com',
            'aud' => 'test-client-id',
            'iat' => time(),
            'jti' => 'unique-id',
            'events' => [
                'http://schemas.openid.net/event/backchannel-logout' => [],
            ],
            'sid' => 'session-123',
        ];
        $token = LogoutToken::from($this->createSampleJwt($payload));

        $this->assertNull($token->subject());
    }

    public function testSessionId(): void
    {
        $token = LogoutToken::from($this->createSampleLogoutToken([
            'sid' => 'session-456',
        ]));

        $this->assertSame('session-456', $token->sessionId());
    }

    public function testSessionIdNull(): void
    {
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
        $token = LogoutToken::from($this->createSampleJwt($payload));

        $this->assertNull($token->sessionId());
    }

    public function testIssuedAt(): void
    {
        $iat = time();
        $token = LogoutToken::from($this->createSampleLogoutToken([
            'iat' => $iat,
        ]));

        $this->assertSame($iat, $token->issuedAt());
    }

    public function testJwtId(): void
    {
        $token = LogoutToken::from($this->createSampleLogoutToken([
            'jti' => 'unique-jwt-id-789',
        ]));

        $this->assertSame('unique-jwt-id-789', $token->jwtId());
    }

    public function testEvents(): void
    {
        $events = [
            'http://schemas.openid.net/event/backchannel-logout' => [],
        ];
        $token = LogoutToken::from($this->createSampleLogoutToken([
            'events' => $events,
        ]));

        $this->assertSame($events, $token->events());
    }

    public function testEventsInvalidType(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Events claim must be an array');

        $token = LogoutToken::from($this->createSampleLogoutToken([
            'events' => 'not-an-array',
        ]));

        $token->events();
    }

    public function testClaims(): void
    {
        $payload = [
            'iss' => 'https://example.com',
            'aud' => 'test-client-id',
            'iat' => time(),
            'jti' => 'unique-id',
            'events' => [
                'http://schemas.openid.net/event/backchannel-logout' => [],
            ],
            'sub' => 'user-123',
            'sid' => 'session-456',
        ];
        $token = LogoutToken::from($this->createSampleJwt($payload));

        $claims = $token->claims();
        $this->assertArrayHasKey('iss', $claims);
        $this->assertArrayHasKey('aud', $claims);
        $this->assertArrayHasKey('iat', $claims);
        $this->assertArrayHasKey('jti', $claims);
        $this->assertArrayHasKey('events', $claims);
        $this->assertArrayHasKey('sub', $claims);
        $this->assertArrayHasKey('sid', $claims);
    }

    public function testHas(): void
    {
        $token = LogoutToken::from($this->createSampleLogoutToken([
            'sub' => 'user-123',
        ]));

        $this->assertTrue($token->has('sub'));
        $this->assertTrue($token->has('iss'));
        $this->assertFalse($token->has('nonexistent'));
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
            'sid' => 'session-456',
        ];

        $payload = array_merge($defaultPayload, $payload);

        return $this->createSampleJwt($payload);
    }
}
