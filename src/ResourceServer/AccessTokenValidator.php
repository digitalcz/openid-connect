<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\IntrospectionException;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;

/**
 * Validation strategy interface
 */
interface AccessTokenValidator
{
    /**
     * Check if validator supports token type
     */
    public function supports(AccessToken $token): bool;

    /**
     * Validate access token
     *
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws IntrospectionException if the introspection endpoint request fails (opaque tokens)
     * @throws InvalidTokenException if the token is malformed, unsupported, or fails validation
     * @throws NetworkException if a required endpoint cannot be reached
     */
    public function validate(AccessToken $token): ValidatedAccessToken;
}
