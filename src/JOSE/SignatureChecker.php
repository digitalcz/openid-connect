<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use DigitalCz\OpenIDConnect\Exception\AuthorizationException;
use DigitalCz\OpenIDConnect\ProviderMetadata;
use Jose\Component\Signature\JWSLoader;

final class SignatureChecker implements SignatureCheckerInterface
{
    public function __construct(private ProviderMetadata $providerMetadata, private JOSEFactory $JOSEFactory)
    {
    }

    public function check(string $token): void
    {
        $jwks = $this->providerMetadata->getJwks()
            ?? throw new AuthorizationException('Cannot check token signature without JWKs.');
        $this->createJWSLoader()->loadAndVerifyWithKeySet($token, $jwks, $signature);
    }

    private function createJWSLoader(): JWSLoader
    {
        return $this->JOSEFactory->createJWSLoader($this->providerMetadata);
    }
}
