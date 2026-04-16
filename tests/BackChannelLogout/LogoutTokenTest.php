<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Stringable;
use UnexpectedValueException;

#[CoversClass(LogoutToken::class)]
class LogoutTokenTest extends TestCase
{
    public function testConstructor(): void
    {
        $jwt = $this->createSampleLogoutJwt();
        $token = new LogoutToken($jwt);

        $this->assertSame($jwt, (string) $token);
    }

    public function testFromStringReturnsToken(): void
    {
        $jwt = $this->createSampleLogoutJwt();

        $token = LogoutToken::from($jwt);

        $this->assertInstanceOf(LogoutToken::class, $token);
        $this->assertSame($jwt, (string) $token);
    }

    public function testFromArrayWithLogoutTokenKey(): void
    {
        $jwt = $this->createSampleLogoutJwt();

        $token = LogoutToken::from(['logout_token' => $jwt]);

        $this->assertSame($jwt, (string) $token);
    }

    public function testFromArrayWithoutLogoutTokenKeyThrows(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Cannot create LogoutToken from array without "logout_token" key');

        LogoutToken::from(['id_token' => 'foo']);
    }

    public function testFromStringable(): void
    {
        $jwt = $this->createSampleLogoutJwt();
        $stringable = new class ($jwt) implements Stringable {
            public function __construct(private string $value)
            {
            }

            public function __toString(): string
            {
                return $this->value;
            }
        };

        $token = LogoutToken::from($stringable);

        $this->assertSame($jwt, (string) $token);
    }

    public function testFromNonStringThrows(): void
    {
        $this->expectException(UnexpectedValueException::class);

        LogoutToken::from(123);
    }

    public function testFromInvalidJwtThrows(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid JWT logout token format');

        LogoutToken::from('not-a-jwt');
    }

    public function testTryFromReturnsNullOnInvalid(): void
    {
        $this->assertNull(LogoutToken::tryFrom('not-a-jwt'));
        $this->assertNull(LogoutToken::tryFrom(['foo' => 'bar']));
        $this->assertNull(LogoutToken::tryFrom(123));
    }

    public function testTryFromReturnsTokenOnValid(): void
    {
        $jwt = $this->createSampleLogoutJwt();

        $token = LogoutToken::tryFrom($jwt);

        $this->assertInstanceOf(LogoutToken::class, $token);
    }

    public function testIss(): void
    {
        $jwt = $this->createSampleLogoutJwt(['iss' => 'https://op.example.com']);
        $token = new LogoutToken($jwt);

        $this->assertSame('https://op.example.com', $token->iss());
    }

    public function testAudAsString(): void
    {
        $jwt = $this->createSampleLogoutJwt(['aud' => 'client-id']);
        $token = new LogoutToken($jwt);

        $this->assertSame('client-id', $token->aud());
    }

    public function testAudAsArray(): void
    {
        $jwt = $this->createSampleLogoutJwt(['aud' => ['client-a', 'client-b']]);
        $token = new LogoutToken($jwt);

        $this->assertSame(['client-a', 'client-b'], $token->aud());
    }

    public function testIat(): void
    {
        $jwt = $this->createSampleLogoutJwt(['iat' => 1700000000]);
        $token = new LogoutToken($jwt);

        $this->assertSame(1700000000, $token->iat());
    }

    public function testJti(): void
    {
        $jwt = $this->createSampleLogoutJwt(['jti' => 'unique-jti-123']);
        $token = new LogoutToken($jwt);

        $this->assertSame('unique-jti-123', $token->jti());
    }

    public function testSubPresent(): void
    {
        $jwt = $this->createSampleLogoutJwt(['sub' => 'user-1']);
        $token = new LogoutToken($jwt);

        $this->assertSame('user-1', $token->sub());
    }

    public function testSubAbsent(): void
    {
        $payload = $this->sampleLogoutPayload();
        unset($payload['sub']);
        $jwt = $this->createCustomJwt(['typ' => 'JWT', 'alg' => 'RS256'], $payload);
        $token = new LogoutToken($jwt);

        $this->assertNull($token->sub());
    }

    public function testSidPresent(): void
    {
        $jwt = $this->createSampleLogoutJwt(['sid' => 'session-abc']);
        $token = new LogoutToken($jwt);

        $this->assertSame('session-abc', $token->sid());
    }

    public function testSidAbsent(): void
    {
        $jwt = $this->createSampleLogoutJwt(); // no sid by default
        $token = new LogoutToken($jwt);

        $this->assertNull($token->sid());
    }

    public function testEventsReturnsArray(): void
    {
        $events = [JwtLogoutTokenValidator::LOGOUT_EVENT_URI => (object) []];
        $jwt = $this->createSampleLogoutJwt(['events' => $events]);
        $token = new LogoutToken($jwt);

        // object is decoded as empty array on JSON decode to associative
        $this->assertArrayHasKey(JwtLogoutTokenValidator::LOGOUT_EVENT_URI, $token->events());
    }

    public function testEventsThrowsWhenMissing(): void
    {
        $payload = $this->sampleLogoutPayload();
        unset($payload['events']);
        $jwt = $this->createCustomJwt(['typ' => 'JWT', 'alg' => 'RS256'], $payload);
        $token = new LogoutToken($jwt);

        $this->expectException(UnexpectedValueException::class);

        $token->events();
    }

    public function testClaims(): void
    {
        $jwt = $this->createSampleLogoutJwt(['sub' => 'user-42', 'sid' => 'sess-42']);
        $token = new LogoutToken($jwt);

        $claims = $token->claims();

        $this->assertSame('user-42', $claims['sub']);
        $this->assertSame('sess-42', $claims['sid']);
    }

    public function testToString(): void
    {
        $jwt = $this->createSampleLogoutJwt();
        $token = new LogoutToken($jwt);

        $this->assertSame($jwt, (string) $token);
        $this->assertSame($jwt, $token->__toString());
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function createSampleLogoutJwt(array $overrides = []): string
    {
        return $this->createCustomJwt(
            ['typ' => 'logout+jwt', 'alg' => 'RS256', 'kid' => 'test-key-id'],
            array_merge($this->sampleLogoutPayload(), $overrides),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function sampleLogoutPayload(): array
    {
        return [
            'iss' => 'https://auth.example.com',
            'aud' => 'test-client-id',
            'iat' => time(),
            'jti' => 'jti-12345',
            'sub' => 'user-42',
            'events' => [
                JwtLogoutTokenValidator::LOGOUT_EVENT_URI => [],
            ],
        ];
    }
}
