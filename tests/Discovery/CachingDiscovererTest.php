<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

#[CoversClass(CachingDiscoverer::class)]
class CachingDiscovererTest extends TestCase
{
    public function testDiscoverUsesCacheOnSuccess(): void
    {
        $issuer = 'https://example.com';
        $expectedMetadata = new IssuerMetadata(['issuer' => $issuer]);

        $innerDiscoverer = $this->createMock(Discoverer::class);
        $cache = $this->createMock(CacheInterface::class);
        $item = $this->createMock(ItemInterface::class);

        $cache->expects($this->once())
            ->method('get')
            ->with($this->stringContains('oidc_discoverer_'))
            ->willReturnCallback(
                static fn (string $key, callable $callback): IssuerMetadata => $callback($item),
            );

        $item->expects($this->once())
            ->method('expiresAfter')
            ->with(CachingDiscoverer::DEFAULT_TTL);

        $innerDiscoverer->expects($this->once())
            ->method('discover')
            ->with($issuer)
            ->willReturn($expectedMetadata);

        $cachingDiscoverer = new CachingDiscoverer($innerDiscoverer, $cache);
        $result = $cachingDiscoverer->discover($issuer);

        $this->assertSame($expectedMetadata, $result);
    }

    public function testDiscoverUsesCustomTtl(): void
    {
        $issuer = 'https://example.com';
        $customTtl = 7200;
        $expectedMetadata = new IssuerMetadata(['issuer' => $issuer]);

        $innerDiscoverer = $this->createMock(Discoverer::class);
        $cache = $this->createMock(CacheInterface::class);
        $item = $this->createMock(ItemInterface::class);

        $cache->expects($this->once())
            ->method('get')
            ->willReturnCallback(
                static fn (string $key, callable $callback): IssuerMetadata => $callback($item),
            );

        $item->expects($this->once())
            ->method('expiresAfter')
            ->with($customTtl);

        $innerDiscoverer->expects($this->once())
            ->method('discover')
            ->with($issuer)
            ->willReturn($expectedMetadata);

        $cachingDiscoverer = new CachingDiscoverer($innerDiscoverer, $cache, $customTtl);
        $result = $cachingDiscoverer->discover($issuer);

        $this->assertSame($expectedMetadata, $result);
    }

    public function testDiscoverUsesHmacCacheKey(): void
    {
        $issuer = 'https://example.com';
        $cacheSecret = 'test-secret';
        $expectedKey = 'oidc_discoverer_' . hash_hmac('sha256', $issuer, $cacheSecret);
        $expectedMetadata = new IssuerMetadata(['issuer' => $issuer]);

        $innerDiscoverer = $this->createMock(Discoverer::class);
        $cache = $this->createMock(CacheInterface::class);
        $item = $this->createMock(ItemInterface::class);

        $cache->expects($this->once())
            ->method('get')
            ->with($expectedKey)
            ->willReturnCallback(
                static fn (string $key, callable $callback): IssuerMetadata => $callback($item),
            );

        $item->expects($this->once())
            ->method('expiresAfter');

        $innerDiscoverer->expects($this->once())
            ->method('discover')
            ->willReturn($expectedMetadata);

        $cachingDiscoverer = new CachingDiscoverer(
            $innerDiscoverer,
            $cache,
            CachingDiscoverer::DEFAULT_TTL,
            $cacheSecret,
        );

        $cachingDiscoverer->discover($issuer);
    }
}
