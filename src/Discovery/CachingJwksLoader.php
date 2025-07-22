<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Util\Base64Url;
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
    ) {
    }

    /**
     * @return mixed[]
     */
    public function load(string $jwksUri): array
    {
        $cacheKey = 'oidc_jwks_' . Base64Url::encode($jwksUri);

        return $this->cache->get($cacheKey, function (ItemInterface $item) use ($jwksUri): array {
            $item->expiresAfter($this->ttl); // Cache for 1 hour

            return $this->inner->load($jwksUri);
        });
    }
}
