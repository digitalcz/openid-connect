<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

/**
 * Exception thrown when a logout token has expired.
 */
class LogoutTokenExpiredException extends InvalidLogoutTokenException
{
}
