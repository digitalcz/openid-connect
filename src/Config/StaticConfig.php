<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

/**
 * Pre-configured static metadata
 */
final readonly class StaticConfig implements Config
{
    public function __construct(
        private IssuerMetadata $issuerMetadata,
        private ClientMetadata $clientMetadata,
    ) {
    }

    public function issuerMetadata(): IssuerMetadata
    {
        return $this->issuerMetadata;
    }

    public function clientMetadata(): ClientMetadata
    {
        return $this->clientMetadata;
    }
}
