<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;

/**
 * Interface for JWKS loading.
 */
interface JwksLoader
{
    /**
     * Loads JWKS from URI.
     *
     * @return mixed[]
     *
     * @throws DiscoveryException if the JWKS document cannot be fetched or is invalid
     * @throws NetworkException if the JWKS endpoint cannot be reached
     */
    public function load(string $jwksUri): array;
}
