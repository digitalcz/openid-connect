<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Param;

use Jose\Component\Checker\ClaimChecker;

final class ClaimsChecks
{
    /**
     * @param string[] $mandatoryClaims
     * @param ClaimChecker[] $checkers
     */
    public function __construct(private readonly array $mandatoryClaims = [], private readonly array $checkers = [])
    {
    }

    /**
     * @return string[]
     */
    public function mandatoryClaims(): array
    {
        return $this->mandatoryClaims;
    }

    /**
     * @return ClaimChecker[]
     */
    public function checkers(): array
    {
        return $this->checkers;
    }
}
