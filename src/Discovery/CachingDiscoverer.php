<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Util\Base64Url;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Caching decorator for discovery.
 */
final readonly class CachingDiscoverer implements Discoverer
{
    public const int DEFAULT_TTL = 3600;

    public function __construct(
        private Discoverer $inner,
        private CacheInterface $cache,
        private int $ttl = self::DEFAULT_TTL,
    ) {
    }

    public function discover(string $issuer): IssuerMetadata
    {
        $key = 'oidc_discoverer_' . Base64Url::encode($issuer);

        return $this->cache->get($key, function (ItemInterface $item) use ($issuer): IssuerMetadata {
            $item->expiresAfter($this->ttl);

            return $this->inner->discover($issuer);
        });
    }
}
