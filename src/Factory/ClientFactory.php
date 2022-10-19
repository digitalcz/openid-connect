<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Factory;

use DigitalCz\OpenIDConnect\Client;
use DigitalCz\OpenIDConnect\ClientMetadata;
use DigitalCz\OpenIDConnect\Config;
use DigitalCz\OpenIDConnect\Http\HttpClient;
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
        $tokenVerifier = TokenVerifierFactory::create($config);

        return new Client($config, $httpClient, $tokenVerifier);
    }
}
