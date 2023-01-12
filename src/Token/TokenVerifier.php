<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Token;

use DigitalCz\OpenIDConnect\JOSE\Claims;
use DigitalCz\OpenIDConnect\JOSE\ClaimsCheckerInterface;
use DigitalCz\OpenIDConnect\JOSE\SignatureCheckerInterface;
use DigitalCz\OpenIDConnect\Param\ClaimsChecks;

final class TokenVerifier implements TokenVerifierInterface
{
    public function __construct(
        private readonly SignatureCheckerInterface $signatureChecker,
        private readonly ClaimsCheckerInterface $claimsChecker,
    ) {
    }

    public function verify(string $token, ClaimsChecks $checks): void
    {
        $this->signatureChecker->check($token);
        $this->claimsChecker->check(Claims::fromToken($token), $checks);
    }
}
