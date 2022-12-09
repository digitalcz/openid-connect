<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Token;

use DigitalCz\OpenIDConnect\JOSE\ClaimsChecker;
use DigitalCz\OpenIDConnect\JOSE\JOSEFactory;
use DigitalCz\OpenIDConnect\JOSE\SignatureChecker;
use DigitalCz\OpenIDConnect\ProviderMetadata;

final class TokenVerifierFactory
{
    public static function create(
        ProviderMetadata $providerMetadata,
        ?SignatureChecker $signatureChecker = null,
        ?ClaimsChecker $claimsChecker = null
    ): TokenVerifier {
        $signatureChecker ??= new SignatureChecker($providerMetadata, new JOSEFactory());
        $claimsChecker ??= new ClaimsChecker();

        return new TokenVerifier($signatureChecker, $claimsChecker);
    }
}
