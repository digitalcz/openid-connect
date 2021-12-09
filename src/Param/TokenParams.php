<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Param;

use DigitalCz\OpenIDConnect\Grant\GrantType;

final class TokenParams extends Params
{
    public const CODE = 'code';
    public const GRANT_TYPE = 'grant_type';

    /**
     * @param GrantType $grantType
     * @param array<string, mixed> $parameters
     */
    public function __construct(private GrantType $grantType, array $parameters = [])
    {
        parent::__construct($parameters);
    }

    public function getGrantType(): GrantType
    {
        return $this->grantType;
    }
}
