<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

interface Config
{
    public function issuerMetadata(): IssuerMetadata;

    public function clientMetadata(): ClientMetadata;
}
