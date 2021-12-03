<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Grant;

final class AuthorizationCode extends GrantType
{
    public function getType(): string
    {
        return 'authorization_code';
    }

    /**
     * @return string[]
     */
    protected function getRequiredParams(): array
    {
        return ['code'];
    }
}
