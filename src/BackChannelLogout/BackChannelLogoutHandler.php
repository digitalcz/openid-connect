<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use UnexpectedValueException;

/**
 * Entry point for processing OpenID Connect Back-Channel Logout requests.
 *
 * Applications should call {@see self::handleLogoutRequest()} with the
 * `logout_token` POST parameter received on their back-channel logout
 * endpoint. On success the returned {@see LogoutToken} exposes `sub` and/or
 * `sid`, which the application uses to terminate the relevant sessions.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html
 */
final readonly class BackChannelLogoutHandler
{
    public function __construct(
        private LogoutTokenValidator $validator,
    ) {
    }

    /**
     * Parses and validates a logout token string.
     *
     * @throws InvalidTokenException when the token is malformed or fails validation
     */
    public function handleLogoutRequest(string $logoutToken): LogoutToken
    {
        try {
            $token = LogoutToken::from($logoutToken);
        } catch (UnexpectedValueException $e) {
            throw new InvalidTokenException('Invalid Logout Token: ' . $e->getMessage(), 0, $e);
        }

        $this->validator->validate($token);

        return $token;
    }
}
