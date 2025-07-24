<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

use LogicException;

/**
 * Exception thrown when there is a configuration or setup error.
 */
final class ConfigurationException extends LogicException implements Exception
{
}
