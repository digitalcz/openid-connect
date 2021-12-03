<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Token;

use DigitalCz\OpenIDConnect\JOSE\Claims;
use DigitalCz\OpenIDConnect\JOSE\ClaimsCheckerInterface;
use DigitalCz\OpenIDConnect\JOSE\SignatureCheckerInterface;
use DigitalCz\OpenIDConnect\Param\CallbackChecks;

final class TokenVerifier implements TokenVerifierInterface
{
    public function __construct(
        private SignatureCheckerInterface $signatureChecker,
        private ClaimsCheckerInterface $claimsChecker
    ) {
    }

    public function verify(string $token, CallbackChecks $checks): void
    {
        $this->signatureChecker->check($token);
        $this->claimsChecker->check(Claims::fromToken($token), $checks);
    }
}
