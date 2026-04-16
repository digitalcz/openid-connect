<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

/**
 * Thrown when the device is polling the token endpoint too frequently.
 *
 * RFC 8628 section 3.5 - "slow_down". The polling interval MUST be
 * increased by 5 seconds after receiving this error.
 */
final class SlowDownException extends DeviceAuthorizationException
{
}
