<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Factory;

use DigitalCz\OpenIDConnect\Config;
use DigitalCz\OpenIDConnect\JOSE\ClaimsChecker;
use DigitalCz\OpenIDConnect\JOSE\JOSEFactory;
use DigitalCz\OpenIDConnect\JOSE\SignatureChecker;
use DigitalCz\OpenIDConnect\Token\TokenVerifier;

final class TokenVerifierFactory
{
    public static function create(Config $config): TokenVerifier
    {
        return new TokenVerifier(new SignatureChecker($config, new JOSEFactory()), new ClaimsChecker($config));
    }
}
