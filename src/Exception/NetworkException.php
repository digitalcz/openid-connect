<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

use RuntimeException;

/**
 * Exception thrown when HTTP client or network-related operations fail.
 */
final class NetworkException extends RuntimeException implements Exception
{
}
