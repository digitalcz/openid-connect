<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Config\IssuerMetadata;

interface Discoverer
{
    public function discover(string $issuer): IssuerMetadata;
}
