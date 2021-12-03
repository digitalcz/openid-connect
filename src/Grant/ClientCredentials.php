<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Grant;

final class ClientCredentials extends GrantType
{
    public function getType(): string
    {
        return 'client_credentials';
    }

    /**
     * @return string[]
     */
    protected function getRequiredParams(): array
    {
        return [];
    }
}
