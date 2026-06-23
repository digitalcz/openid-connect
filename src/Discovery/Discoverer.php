<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;

/**
 * Interface for OIDC discovery implementations.
 */
interface Discoverer
{
    /**
     * Discovers OIDC provider metadata from issuer.
     *
     * @throws DiscoveryException if the discovery document cannot be fetched or is invalid
     * @throws NetworkException if the discovery endpoint cannot be reached
     */
    public function discover(string $issuer): IssuerMetadata;
}
