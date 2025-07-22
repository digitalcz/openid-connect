<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use Stringable;
use UnexpectedValueException;

use function is_array;
use function is_scalar;
use function sprintf;

/**
 * Type-safe parameter access trait
 */
trait ParamsTrait
{
    /**
     * Check if a parameter exists in the collection.
     *
     * @param string $key The name of the parameter to check.
     * @return bool True if the parameter exists, false otherwise.
     */
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->all());
    }

    /**
     * Get parameter value or default
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->has($key) ? $this->all()[$key] : $default;
    }

    /**
     * Get required integer parameter
     */
    public function integer(string $key): int
    {
        $value = $this->get($key);

        if ($value === null) {
            throw new UnexpectedValueException(sprintf('Parameter "%s" is required and must be an integer.', $key));
        }

        if (!is_int($value)) {
            throw new UnexpectedValueException(sprintf('Parameter value "%s" cannot be converted to "integer".', $key));
        }

        return $value;
    }

    /**
     * Get required boolean parameter
     */
    public function boolean(string $key): bool
    {
        $value = $this->get($key);

        if ($value === null) {
            throw new UnexpectedValueException(sprintf('Parameter "%s" is required and must be a boolean.', $key));
        }

        if (!is_bool($value)) {
            throw new UnexpectedValueException(sprintf('Parameter value "%s" cannot be converted to "boolean".', $key));
        }

        return $value;
    }

    /**
     * Get required string parameter
     */
    public function string(string $key): string
    {
        $value = $this->get($key);

        if ($value === null) {
            throw new UnexpectedValueException(sprintf('Parameter "%s" is required and must be a string.', $key));
        }

        if ($value instanceof Stringable) {
            $value = (string)$value;
        }

        if (!is_string($value)) {
            throw new UnexpectedValueException(sprintf('Parameter value "%s" cannot be converted to "string".', $key));
        }

        return $value;
    }

    /**
     * Get required string array parameter
     *
     * @return string[]
     */
    public function strings(string $key): array
    {
        $value = $this->get($key);

        if ($value === null) {
            throw new UnexpectedValueException(
                sprintf('Parameter "%s" is required and must be an array of strings.', $key),
            );
        }

        if (!is_array($value)) {
            throw new UnexpectedValueException(sprintf('Parameter value "%s" cannot be converted to "array".', $key));
        }

        $strings = [];

        foreach ($value as $item) {
            if (!is_scalar($item) && !$item instanceof Stringable) {
                throw new UnexpectedValueException(
                    sprintf('Parameter value "%s" cannot be converted to "string".', $key),
                );
            }

            $strings[] = (string)$item;
        }

        return $strings;
    }

    /** @return array<string, mixed> */
    abstract public function all(): array;
}
