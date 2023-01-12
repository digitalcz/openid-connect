<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Http;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;

final class HttpClientFactory
{
    public static function create(
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?UriFactoryInterface $uriFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
    ): HttpClient {
        return new HttpClient(
            $httpClient ?? Psr18ClientDiscovery::find(),
            $requestFactory ?? Psr17FactoryDiscovery::findRequestFactory(),
            $uriFactory ?? Psr17FactoryDiscovery::findUriFactory(),
            $streamFactory ?? Psr17FactoryDiscovery::findStreamFactory(),
        );
    }
}
