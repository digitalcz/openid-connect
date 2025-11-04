<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

/**
 * Exception thrown when a logout token signature is invalid or issuer is untrusted.
 */
class UntrustedLogoutTokenException extends InvalidLogoutTokenException
{
}
