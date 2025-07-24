<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

use RuntimeException;

/**
 * Exception thrown when token introspection endpoint operations fail.
 */
final class IntrospectionException extends RuntimeException implements Exception
{
}
