<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Caching decorator for JWKS.
 */
final readonly class CachingJwksLoader implements JwksLoader
{
    public const int DEFAULT_TTL = 3600;

    public function __construct(
        private JwksLoader $inner,
        private CacheInterface $cache,
        private int $ttl = self::DEFAULT_TTL,
        private string $cacheSecret = 'default-oidc-cache-secret',
    ) {
    }

    /**
     * @return mixed[]
     */
    public function load(string $jwksUri): array
    {
        $cacheKey = 'oidc_jwks_' . hash_hmac('sha256', $jwksUri, $this->cacheSecret);

        return $this->cache->get($cacheKey, function (ItemInterface $item) use ($jwksUri): array {
            $item->expiresAfter($this->ttl); // Cache for 1 hour

            return $this->inner->load($jwksUri);
        });
    }
}
