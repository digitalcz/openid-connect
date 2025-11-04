<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

/**
 * Exception thrown when a logout token is malformed or contains invalid data.
 */
class InvalidLogoutTokenException extends InvalidTokenException
{
}
