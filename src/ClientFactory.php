<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Discovery\DiscovererFactory;
use DigitalCz\OpenIDConnect\Http\HttpClient;
use DigitalCz\OpenIDConnect\Http\HttpClientFactory;
use Psr\SimpleCache\CacheInterface;

final class ClientFactory
{
    public static function create(
        string $issuerUrl,
        ClientMetadata $clientMetadata,
        ?HttpClient $httpClient = null,
        ?CacheInterface $cache = null
    ): Client {
        $httpClient ??= HttpClientFactory::create();
        $discoverer = DiscovererFactory::create($httpClient, $cache);
        $providerMetadata = $discoverer->discover($issuerUrl);
        $config = new Config($providerMetadata, $clientMetadata);

        return new Client($config, $httpClient);
    }
}
