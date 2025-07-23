<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

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
     */
    public function validate(AccessToken $token): ValidatedAccessToken;
}
