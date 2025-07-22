<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

use RuntimeException;

/**
 * Exception thrown when token validation fails.
 */
final class InvalidTokenException extends RuntimeException implements Exception
{
}
