<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\ProviderMetadata;

interface Discoverer
{
    /**
     * @throws DiscoveryException
     */
    public function discover(string $uri): ProviderMetadata;
}
