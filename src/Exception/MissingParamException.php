<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

class MissingParamException extends RuntimeException
{
    public function __construct(string $key)
    {
        parent::__construct("Missing key \"$key\"");
    }
}
