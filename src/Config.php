<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use Psr\Clock\ClockInterface;

final readonly class Config
{
    public function __construct(
        private ProviderMetadata $providerMetadata,
        private ClientMetadata $clientMetadata,
        private ClockInterface $clock = new SimpleClock(),
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

    public function clock(): ClockInterface
    {
        return $this->clock;
    }
}
