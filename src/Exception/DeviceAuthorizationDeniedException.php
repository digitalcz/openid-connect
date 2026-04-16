<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

/**
 * Thrown when the end user denied the device authorization request.
 *
 * RFC 8628 section 3.5 - "access_denied".
 */
final class DeviceAuthorizationDeniedException extends DeviceAuthorizationException
{
}
