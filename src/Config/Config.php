<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;

/**
 * Main configuration interface
 */
interface Config
{
    /**
     * Provider metadata, resolved via discovery for {@see DiscoveryConfig}.
     *
     * @throws DiscoveryException if the discovery document cannot be fetched or is invalid
     * @throws NetworkException if the discovery endpoint cannot be reached
     */
    public function issuerMetadata(): IssuerMetadata;

    public function clientMetadata(): ClientMetadata;
}
