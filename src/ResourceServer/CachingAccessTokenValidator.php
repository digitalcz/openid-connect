<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DateTimeImmutable;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

final readonly class CachingAccessTokenValidator implements AccessTokenValidator
{
    private const string CACHE_PREFIX = 'oidc_token_';
    private const int DEFAULT_TTL = 60;

    public function __construct(
        private AccessTokenValidator $inner,
        private CacheInterface $cache,
        private ClockInterface $clock = new SimpleClock(),
        private int $ttl = self::DEFAULT_TTL,
    ) {
    }

    public function supports(AccessToken $token): bool
    {
        return $this->inner->supports($token);
    }

    public function validate(AccessToken $token): ValidatedAccessToken
    {
        // Use a hashed version of the token as the cache key for security.
        $cacheKey = self::CACHE_PREFIX . hash('sha256', (string)$token);

        return $this->cache->get($cacheKey, function (ItemInterface $item) use ($token): ValidatedAccessToken {
            // If the item is not in the cache, call the real validator.
            $validatedToken = $this->inner->validate($token);
            $now = $this->clock->now()->getTimestamp();
            $exp = $validatedToken->has('exp') ? $validatedToken->exp() : $now + $this->ttl;

            if ($exp < $now) {
                // If the token is already expired, do not cache it.
                throw new InvalidArgumentException('The access token is expired.');
            }

            $item->expiresAt(DateTimeImmutable::createFromTimestamp($exp));

            return $validatedToken;
        });
    }
}
