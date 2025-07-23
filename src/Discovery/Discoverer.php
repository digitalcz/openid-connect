<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Config\IssuerMetadata;

/**
 * Interface for OIDC discovery implementations.
 */
interface Discoverer
{
    /** Discovers OIDC provider metadata from issuer. */
    public function discover(string $issuer): IssuerMetadata;
}
