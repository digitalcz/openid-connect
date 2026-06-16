<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

/**
 * Thrown while the end user has not yet completed the device authorization.
 *
 * RFC 8628 section 3.5 - "authorization_pending".
 */
final class DeviceAuthorizationPendingException extends DeviceAuthorizationException
{
}
