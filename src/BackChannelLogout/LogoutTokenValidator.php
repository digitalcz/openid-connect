<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;

/**
 * Interface for Back-Channel Logout Token validation implementations.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
 */
interface LogoutTokenValidator
{
    /**
     * @throws InvalidTokenException
     */
    public function validate(LogoutToken $token): void;
}
