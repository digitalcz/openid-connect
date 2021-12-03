<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Authentication;

interface AuthenticationMethod
{
    public function getMethod(): string;
}
