<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

final class Config
{
    public function __construct(private ProviderMetadata $providerMetadata, private ClientMetadata $clientMetadata)
    {
    }

    public function getProviderMetadata(): ProviderMetadata
    {
        return $this->providerMetadata;
    }

    public function getClientMetadata(): ClientMetadata
    {
        return $this->clientMetadata;
    }
}
