<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

/**
 * Thrown when the device code has expired before the user completed authorization.
 *
 * RFC 8628 section 3.5 - "expired_token". The device must restart the flow.
 */
final class DeviceAuthorizationExpiredException extends DeviceAuthorizationException
{
}
