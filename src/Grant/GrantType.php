<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Grant;

use InvalidArgumentException;

abstract class GrantType
{
    abstract public function getType(): string;

    /**
     * @param mixed[] $params
     */
    public function checkRequiredParams(array $params): void
    {
        foreach ($this->getRequiredParams() as $requiredParam) {
            if (!isset($params[$requiredParam])) {
                throw new InvalidArgumentException("Missing required param $requiredParam");
            }
        }
    }

    /** @return string[] */
    abstract protected function getRequiredParams(): array;
}
