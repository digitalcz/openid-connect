<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Grant;

final class RefreshToken extends GrantType
{
    public function getType(): string
    {
        return 'refresh_token';
    }

    /**
     * @return string[]
     */
    protected function getRequiredParams(): array
    {
        return ['refresh_token'];
    }
}
