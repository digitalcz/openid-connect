<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

final class Config
{
    public function __construct(
        private readonly ProviderMetadata $providerMetadata,
        private readonly ClientMetadata $clientMetadata
    ) {
    }

    public function providerMetadata(): ProviderMetadata
    {
        return $this->providerMetadata;
    }

    public function clientMetadata(): ClientMetadata
    {
        return $this->clientMetadata;
    }
}
