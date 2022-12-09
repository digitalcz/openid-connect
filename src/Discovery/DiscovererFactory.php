<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Http\HttpClient;
use DigitalCz\OpenIDConnect\Http\HttpClientFactory;
use Psr\SimpleCache\CacheInterface;

final class DiscovererFactory
{
    public static function create(?HttpClient $httpClient = null, ?CacheInterface $cache = null): Discoverer
    {
        $httpClient ??= HttpClientFactory::create();
        $discoverer = new HttpDiscoverer($httpClient);

        if ($cache !== null) {
            $discoverer = new CachedDiscoverer($discoverer, $cache);
        }

        return $discoverer;
    }
}
