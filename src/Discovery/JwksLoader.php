<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

/**
 * Interface for JWKS loading.
 */
interface JwksLoader
{
    /**
     * Loads JWKS from URI.
     *
     * @return mixed[]
     */
    public function load(string $jwksUri): array;
}
