<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

interface JwksLoader
{
    /**
     * @return mixed[]
     */
    public function load(string $jwksUri): array;
}
