<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Discovery\Discoverer;

/**
 * Dynamic configuration via OIDC discovery
 */
final readonly class DiscoveryConfig implements Config
{
    public function __construct(
        private string $issuer,
        private Discoverer $discoverer,
        private ClientMetadata $clientMetadata,
    ) {
    }

    public function issuerMetadata(): IssuerMetadata
    {
        return $this->discoverer->discover($this->issuer);
    }

    public function clientMetadata(): ClientMetadata
    {
        return $this->clientMetadata;
    }
}
