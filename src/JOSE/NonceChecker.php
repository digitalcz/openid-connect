<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

final class NonceChecker implements ClaimChecker
{
    private const CLAIM_NAME = 'nonce';

    public function __construct(private readonly ?string $nonce = null)
    {
    }

    public function checkClaim(mixed $value): void
    {
        if ($this->nonce !== null && $value !== $this->nonce) {
            throw new InvalidClaimException('Invalid nonce.', self::CLAIM_NAME, $value);
        }
    }

    public function supportedClaim(): string
    {
        return self::CLAIM_NAME;
    }
}
