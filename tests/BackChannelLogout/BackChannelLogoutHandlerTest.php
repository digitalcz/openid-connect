<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DigitalCz\OpenIDConnect\Exception\InvalidLogoutTokenException;
use DigitalCz\OpenIDConnect\Exception\LogoutTokenExpiredException;
use DigitalCz\OpenIDConnect\Exception\UntrustedLogoutTokenException;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;

#[CoversClass(BackChannelLogoutHandler::class)]
class BackChannelLogoutHandlerTest extends TestCase
{
    private LogoutTokenValidator&MockObject $validator;
    private BackChannelLogoutHandler $handler;

    protected function setUp(): void
    {
        parent::setUp();

        $this->validator = $this->createMock(LogoutTokenValidator::class);
        $this->handler = new BackChannelLogoutHandler($this->validator);
    }

    public function testConstructor(): void
    {
        $handler = new BackChannelLogoutHandler($this->validator);
        $this->assertInstanceOf(BackChannelLogoutHandler::class, $handler);
    }

    public function testHandleLogoutRequestSuccess(): void
    {
        $tokenString = $this->createSampleLogoutToken();
        $logoutToken = LogoutToken::from($tokenString);

        $this->validator
            ->expects($this->once())
            ->method('validate')
            ->with($tokenString)
            ->willReturn($logoutToken);

        $result = $this->handler->handleLogoutRequest($tokenString);

        $this->assertInstanceOf(LogoutToken::class, $result);
        $this->assertSame($tokenString, (string) $result);
    }

    public function testHandleLogoutRequestWithInvalidToken(): void
    {
        $tokenString = 'invalid-token';

        $this->validator
            ->expects($this->once())
            ->method('validate')
            ->with($tokenString)
            ->willThrowException(new InvalidLogoutTokenException('Invalid token'));

        $this->expectException(InvalidLogoutTokenException::class);
        $this->expectExceptionMessage('Invalid token');

        $this->handler->handleLogoutRequest($tokenString);
    }

    public function testHandleLogoutRequestWithExpiredToken(): void
    {
        $tokenString = $this->createSampleLogoutToken();

        $this->validator
            ->expects($this->once())
            ->method('validate')
            ->with($tokenString)
            ->willThrowException(new LogoutTokenExpiredException('Token expired'));

        $this->expectException(LogoutTokenExpiredException::class);
        $this->expectExceptionMessage('Token expired');

        $this->handler->handleLogoutRequest($tokenString);
    }

    public function testHandleLogoutRequestWithUntrustedToken(): void
    {
        $tokenString = $this->createSampleLogoutToken();

        $this->validator
            ->expects($this->once())
            ->method('validate')
            ->with($tokenString)
            ->willThrowException(new UntrustedLogoutTokenException('Signature invalid'));

        $this->expectException(UntrustedLogoutTokenException::class);
        $this->expectExceptionMessage('Signature invalid');

        $this->handler->handleLogoutRequest($tokenString);
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
