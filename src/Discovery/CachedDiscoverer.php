<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\ProviderMetadata;
use Psr\SimpleCache\CacheInterface;

final class CachedDiscoverer implements Discoverer
{
    public const DEFAULT_TTL = 3600;

    public function __construct(
        private Discoverer $inner,
        private CacheInterface $cache,
        private int $ttl = self::DEFAULT_TTL
    ) {
    }

    public function discover(string $uri): ProviderMetadata
    {
        $key = 'oidc_discoverer_' . base64_encode($uri);

        if ($this->cache->has($key)) {
            return $this->cache->get($key);
        }

        $metadata = $this->inner->discover($uri);
        $this->cache->set($key, $metadata, $this->ttl);

        return $metadata;
    }
}
