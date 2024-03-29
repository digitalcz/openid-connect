<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Param;

use DigitalCz\OpenIDConnect\Grant\GrantType;

final class TokenParams extends Params
{
    public const CODE = 'code';
    public const GRANT_TYPE = 'grant_type';
    public const SCOPE = 'scope';

    /**
     * @param array<string, mixed> $parameters
     */
    public function __construct(private readonly GrantType $grantType, array $parameters = [])
    {
        parent::__construct($parameters);
    }

    public function grantType(): GrantType
    {
        return $this->grantType;
    }
}
