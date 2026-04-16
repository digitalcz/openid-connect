<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

use RuntimeException;
use Throwable;

/**
 * Exception thrown when a Device Authorization Grant (RFC 8628) operation fails.
 */
class DeviceAuthorizationException extends RuntimeException implements Exception
{
    public function __construct(
        string $message,
        private readonly ?string $error = null,
        private readonly ?string $errorDescription = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public function error(): ?string
    {
        return $this->error;
    }

    public function errorDescription(): ?string
    {
        return $this->errorDescription;
    }
}
