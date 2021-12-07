<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Param;

final class CallbackParams extends Params
{
    public const CODE = 'code';
    public const STATE = 'state';
    public const ERROR = 'error';
    public const ERROR_DESCRIPTION = 'error_description';

    public function code(): string
    {
        return $this->getString(self::CODE);
    }

    public function state(): ?string
    {
        return $this->get(self::STATE);
    }

    public function error(): ?string
    {
        return $this->get(self::ERROR);
    }

    public function errorDescription(): ?string
    {
        return $this->get(self::ERROR_DESCRIPTION);
    }
}
