<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

#[CoversClass(CachingJwksLoader::class)]
class CachingJwksLoaderTest extends TestCase
{
    public function testLoadUsesCacheOnSuccess(): void
    {
        $jwksUri = 'https://example.com/.well-known/jwks.json';
        $expectedJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test-key']]];

        $innerLoader = $this->createMock(JwksLoader::class);
        $cache = $this->createMock(CacheInterface::class);
        $item = $this->createMock(ItemInterface::class);

        $cache->expects($this->once())
            ->method('get')
            ->with($this->stringContains('oidc_jwks_'))
            ->willReturnCallback(static fn (string $key, callable $callback): array => $callback($item));

        $item->expects($this->once())
            ->method('expiresAfter')
            ->with(CachingJwksLoader::DEFAULT_TTL);

        $innerLoader->expects($this->once())
            ->method('load')
            ->with($jwksUri)
            ->willReturn($expectedJwks);

        $cachingLoader = new CachingJwksLoader($innerLoader, $cache);
        $result = $cachingLoader->load($jwksUri);

        $this->assertSame($expectedJwks, $result);
    }

    public function testLoadUsesCustomTtl(): void
    {
        $jwksUri = 'https://example.com/.well-known/jwks.json';
        $customTtl = 7200;
        $expectedJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test-key']]];

        $innerLoader = $this->createMock(JwksLoader::class);
        $cache = $this->createMock(CacheInterface::class);
        $item = $this->createMock(ItemInterface::class);

        $cache->expects($this->once())
            ->method('get')
            ->willReturnCallback(static fn (string $key, callable $callback): array => $callback($item));

        $item->expects($this->once())
            ->method('expiresAfter')
            ->with($customTtl);

        $innerLoader->expects($this->once())
            ->method('load')
            ->with($jwksUri)
            ->willReturn($expectedJwks);

        $cachingLoader = new CachingJwksLoader($innerLoader, $cache, $customTtl);
        $result = $cachingLoader->load($jwksUri);

        $this->assertSame($expectedJwks, $result);
    }

    public function testLoadUsesHmacCacheKey(): void
    {
        $jwksUri = 'https://example.com/.well-known/jwks.json';
        $cacheSecret = 'test-secret';
        $expectedKey = 'oidc_jwks_' . hash_hmac('sha256', $jwksUri, $cacheSecret);
        $expectedJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test-key']]];

        $innerLoader = $this->createMock(JwksLoader::class);
        $cache = $this->createMock(CacheInterface::class);
        $item = $this->createMock(ItemInterface::class);

        $cache->expects($this->once())
            ->method('get')
            ->with($expectedKey)
            ->willReturnCallback(static fn (string $key, callable $callback): array => $callback($item));

        $item->expects($this->once())
            ->method('expiresAfter');

        $innerLoader->expects($this->once())
            ->method('load')
            ->willReturn($expectedJwks);

        $cachingLoader = new CachingJwksLoader($innerLoader, $cache, CachingJwksLoader::DEFAULT_TTL, $cacheSecret);

        $cachingLoader->load($jwksUri);
    }
}
