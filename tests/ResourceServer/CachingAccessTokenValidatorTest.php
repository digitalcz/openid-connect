<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DateTimeImmutable;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\TestCase;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

#[CoversClass(CachingAccessTokenValidator::class)]
class CachingAccessTokenValidatorTest extends TestCase
{
    private AccessTokenValidator&MockObject $innerValidator;
    private CacheInterface&MockObject $cache;
    private ClockInterface&MockObject $clock;
    private CachingAccessTokenValidator $validator;

    public function testConstructor(): void
    {
        $validator = new CachingAccessTokenValidator($this->innerValidator, $this->cache);

        $this->assertInstanceOf(CachingAccessTokenValidator::class, $validator);
    }

    public function testConstructorUsesDefaultSecret(): void
    {
        $validator = new CachingAccessTokenValidator($this->innerValidator, $this->cache);

        // Test that default secret is used by checking cache key generation
        $token = new OpaqueAccessToken('test-token');
        $expectedCacheKey = 'oidc_token_' . hash_hmac('sha256', 'test-token', 'default-oidc-cache-secret');

        $validatedToken = new ValidatedAccessToken($token, [
            'sub' => 'user123',
            'iss' => 'https://auth.example.com',
            'aud' => 'test-client-id',
            'exp' => time() + 3600,
            'scope' => 'openid profile',
        ]);
        $item = $this->createMock(ItemInterface::class);

        $validator = new CachingAccessTokenValidator(
            $this->innerValidator,
            $this->cache,
            new SimpleClock(),
            60,
        );

        $this->innerValidator->method('validate')->willReturn($validatedToken);
        $item->expects($this->once())->method('expiresAt');

        $capturedCacheKey = null;
        $this->cache
            ->method('get')
            ->willReturnCallback(static function ($cacheKey, $callback) use ($item, &$capturedCacheKey) {
                $capturedCacheKey = $cacheKey;

                return $callback($item);
            });

        $validator->validate($token);

        $this->assertEquals($expectedCacheKey, $capturedCacheKey);
    }

    public function testSupports(): void
    {
        $token = new OpaqueAccessToken('test-token');

        $this->innerValidator
            ->expects($this->once())
            ->method('supports')
            ->with($token)
            ->willReturn(true);

        $result = $this->validator->supports($token);

        $this->assertTrue($result);
    }

    public function testCacheKeyUsesHmacForSecurity(): void
    {
        $token = new OpaqueAccessToken('test-token');
        $validatedToken = new ValidatedAccessToken($token, [
            'sub' => 'user123',
            'iss' => 'https://auth.example.com',
            'aud' => 'test-client-id',
            'exp' => time() + 3600,
            'scope' => 'openid profile',
        ]);
        $item = $this->createMock(ItemInterface::class);

        $this->clock->method('now')->willReturn(new DateTimeImmutable());

        $this->innerValidator->method('validate')->willReturn($validatedToken);

        $item->expects($this->once())->method('expiresAt');

        // Capture the cache key used
        $capturedCacheKey = null;
        $this->cache
            ->expects($this->once())
            ->method('get')
            ->willReturnCallback(static function ($cacheKey, $callback) use ($item, &$capturedCacheKey) {
                $capturedCacheKey = $cacheKey;

                return $callback($item);
            });

        $this->validator->validate($token);

        // Verify cache key uses HMAC format (should be different from simple hash)
        $expectedKey = 'oidc_token_' . hash_hmac('sha256', 'test-token', 'test-secret-key');
        $this->assertEquals($expectedKey, $capturedCacheKey);

        // Verify it's different from simple hash
        $simpleHashKey = 'oidc_token_' . hash('sha256', 'test-token');
        $this->assertNotEquals($simpleHashKey, $capturedCacheKey);
    }

    public function testDifferentSecretsProduceDifferentCacheKeys(): void
    {
        // Test that different secrets produce different cache keys for the same token
        $expectedKey1 = 'oidc_token_' . hash_hmac('sha256', 'test-token', 'secret-1');
        $expectedKey2 = 'oidc_token_' . hash_hmac('sha256', 'test-token', 'secret-2');

        $this->assertNotEquals($expectedKey1, $expectedKey2);
    }

    public function testValidateCallsInnerValidatorWhenNotCached(): void
    {
        $token = new OpaqueAccessToken('test-token');
        $validatedToken = new ValidatedAccessToken($token, [
            'sub' => 'user123',
            'iss' => 'https://auth.example.com',
            'aud' => 'test-client-id',
            'exp' => time() + 3600,
            'scope' => 'openid profile',
        ]);
        $item = $this->createMock(ItemInterface::class);

        $this->clock->method('now')->willReturn(new DateTimeImmutable());

        $this->innerValidator
            ->expects($this->once())
            ->method('validate')
            ->with($token)
            ->willReturn($validatedToken);

        $item->expects($this->once())->method('expiresAt');

        $this->cache
            ->method('get')
            ->willReturnCallback(static fn ($cacheKey, $callback) => $callback($item));

        $result = $this->validator->validate($token);

        $this->assertSame($validatedToken, $result);
    }

    public function testThrowsExceptionForExpiredToken(): void
    {
        $token = new OpaqueAccessToken('test-token');
        $now = time();
        $expiredTime = $now - 3600; // 1 hour ago

        $validatedToken = new ValidatedAccessToken($token, [
            'sub' => 'user123',
            'iss' => 'https://auth.example.com',
            'aud' => 'test-client-id',
            'exp' => $expiredTime,
            'scope' => 'openid profile',
        ]);
        $item = $this->createMock(ItemInterface::class);

        $this->clock->method('now')->willReturn(new DateTimeImmutable());

        $this->innerValidator->method('validate')->willReturn($validatedToken);

        $this->cache
            ->method('get')
            ->willReturnCallback(static fn ($cacheKey, $callback) => $callback($item));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Cannot cache expired access token.');

        $this->validator->validate($token);
    }

    public function testUsesDefaultTtlWhenTokenHasNoExpiration(): void
    {
        $token = new OpaqueAccessToken('test-token');
        // Create token without exp claim
        $validatedToken = new ValidatedAccessToken($token, [
            'sub' => 'user123',
            'iss' => 'https://auth.example.com',
            'aud' => 'test-client-id',
            'scope' => 'openid profile',
        ]);
        $item = $this->createMock(ItemInterface::class);

        $now = new DateTimeImmutable();
        $this->clock->method('now')->willReturn($now);

        $this->innerValidator->method('validate')->willReturn($validatedToken);

        $item
            ->expects($this->once())
            ->method('expiresAt')
            ->with($this->callback(static fn ($dateTime) => $dateTime instanceof DateTimeImmutable &&
                       $dateTime->getTimestamp() === $now->getTimestamp() + 60));

        $this->cache
            ->method('get')
            ->willReturnCallback(static fn ($cacheKey, $callback) => $callback($item));

        $this->validator->validate($token);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->innerValidator = $this->createMock(AccessTokenValidator::class);
        $this->cache = $this->createMock(CacheInterface::class);
        $this->clock = $this->createMock(ClockInterface::class);

        $this->validator = new CachingAccessTokenValidator(
            $this->innerValidator,
            $this->cache,
            $this->clock,
            60,
            'test-secret-key',
        );
    }
}
