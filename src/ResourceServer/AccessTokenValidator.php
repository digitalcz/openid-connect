<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

interface AccessTokenValidator
{
    public function supports(AccessToken $token): bool;

    public function validate(AccessToken $token): ValidatedAccessToken;
}
