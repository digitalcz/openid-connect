<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;

interface IdTokenValidator
{
    /**
     * @throws InvalidTokenException
     */
    public function validate(IdToken $token, ?string $nonce = null): void;
}
