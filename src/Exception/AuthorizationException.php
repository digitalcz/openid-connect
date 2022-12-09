<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

class AuthorizationException extends RuntimeException
{
    public static function error(string $error, ?string $errorDescription = null): self
    {
        if ($errorDescription !== null) {
            $error .= ': ' . $errorDescription;
        }

        return new self($error);
    }

    public static function stateMismatch(?string $expected, ?string $actual): self
    {
        return new self(sprintf('State mismatch, expected: %s, got %s', $expected, $actual));
    }
}
