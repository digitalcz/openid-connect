<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;

#[CoversClass(BackChannelLogoutHandler::class)]
class BackChannelLogoutHandlerTest extends TestCase
{
    private LogoutTokenValidator&MockObject $validator;

    public function testHandleLogoutRequestReturnsParsedToken(): void
    {
        $jwt = $this->createLogoutJwt();
        $handler = new BackChannelLogoutHandler($this->validator);

        $this->validator
            ->expects($this->once())
            ->method('validate')
            ->with($this->callback(static fn (LogoutToken $t): bool => (string) $t === $jwt));

        $token = $handler->handleLogoutRequest($jwt);

        $this->assertInstanceOf(LogoutToken::class, $token);
        $this->assertSame($jwt, (string) $token);
    }

    public function testHandleLogoutRequestWithMalformedJwtThrows(): void
    {
        $handler = new BackChannelLogoutHandler($this->validator);

        $this->validator->expects($this->never())->method('validate');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid Logout Token');
        $handler->handleLogoutRequest('not-a-jwt');
    }

    public function testHandleLogoutRequestPropagatesValidatorFailure(): void
    {
        $handler = new BackChannelLogoutHandler($this->validator);

        $this->validator
            ->method('validate')
            ->willThrowException(new InvalidTokenException('Invalid Logout Token: boom'));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('boom');
        $handler->handleLogoutRequest($this->createLogoutJwt());
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->validator = $this->createMock(LogoutTokenValidator::class);
    }

    private function createLogoutJwt(): string
    {
        return $this->createCustomJwt(
            ['typ' => 'logout+jwt', 'alg' => 'RS256', 'kid' => 'test-key-id'],
            [
                'iss' => 'https://auth.example.com',
                'aud' => 'test-client-id',
                'iat' => time(),
                'jti' => 'jti-test',
                'sub' => 'user-1',
                'events' => [JwtLogoutTokenValidator::LOGOUT_EVENT_URI => []],
            ],
        );
    }
}
