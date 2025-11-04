<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DigitalCz\OpenIDConnect\Exception\InvalidLogoutTokenException;
use DigitalCz\OpenIDConnect\Exception\LogoutTokenExpiredException;
use DigitalCz\OpenIDConnect\Exception\UntrustedLogoutTokenException;

/**
 * Handles Back-Channel Logout requests from the OpenID Provider.
 */
final readonly class BackChannelLogoutHandler
{
    public function __construct(
        private LogoutTokenValidator $validator,
    ) {
    }

    /**
     * Processes a back-channel logout request.
     *
     * @param string $logoutToken The logout token JWT string
     * @return LogoutToken The validated logout token
     *
     * @throws InvalidLogoutTokenException If the token is malformed or invalid
     * @throws LogoutTokenExpiredException If the token has expired
     * @throws UntrustedLogoutTokenException If the token signature is invalid
     */
    public function handleLogoutRequest(string $logoutToken): LogoutToken
    {
        return $this->validator->validate($logoutToken);
    }
}
