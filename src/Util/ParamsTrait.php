<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use Stringable;
use UnexpectedValueException;

use function is_array;
use function is_scalar;
use function sprintf;

trait ParamsTrait
{
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->all());
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->has($key) ? $this->all()[$key] : $default;
    }

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

    public function string(string $key): string
    {
        $value = $this->get($key);

        if ($value === null) {
            throw new UnexpectedValueException(sprintf('Parameter "%s" is required and must be a string.', $key));
        }

        if (!is_scalar($value) && !$value instanceof Stringable) {
            throw new UnexpectedValueException(sprintf('Parameter value "%s" cannot be converted to "string".', $key));
        }

        return (string)$value;
    }

    /**
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
