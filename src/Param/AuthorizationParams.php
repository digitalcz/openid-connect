<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Param;

final class AuthorizationParams extends Params
{
    public const STATE = 'state';
    public const NONCE = 'nonce';
    public const RESPONSE_TYPE = 'response_type';
}
