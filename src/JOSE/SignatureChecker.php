<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use DigitalCz\OpenIDConnect\Exception\AuthorizationException;
use DigitalCz\OpenIDConnect\ProviderMetadata;
use Jose\Component\Signature\JWSLoader;

final class SignatureChecker implements SignatureCheckerInterface
{
    public function __construct(
        private readonly ProviderMetadata $providerMetadata,
        private readonly JOSEFactory $JOSEFactory
    ) {
    }

    public function check(string $token): void
    {
        $jwkSet = $this->providerMetadata->jwks()
            ?? throw new AuthorizationException('Cannot check token signature without JWKs.');
        $this->createJWSLoader()->loadAndVerifyWithKeySet($token, $jwkSet, $signature);
    }

    private function createJWSLoader(): JWSLoader
    {
        return $this->JOSEFactory->createJWSLoader($this->providerMetadata);
    }
}
