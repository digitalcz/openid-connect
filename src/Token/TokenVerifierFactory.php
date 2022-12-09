<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Token;

use DigitalCz\OpenIDConnect\Config;
use DigitalCz\OpenIDConnect\JOSE\ClaimsChecker;
use DigitalCz\OpenIDConnect\JOSE\JOSEFactory;
use DigitalCz\OpenIDConnect\JOSE\SignatureChecker;

final class TokenVerifierFactory
{
    public static function create(
        Config $config,
        ?SignatureChecker $signatureChecker = null,
        ?ClaimsChecker $claimsChecker = null
    ): TokenVerifier {
        $signatureChecker ??= new SignatureChecker($config->providerMetadata(), new JOSEFactory());
        $claimsChecker ??= new ClaimsChecker();

        return new TokenVerifier($signatureChecker, $claimsChecker);
    }
}
