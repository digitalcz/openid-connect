<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use DigitalCz\OpenIDConnect\Config;
use Jose\Component\Signature\JWSLoader;

final class SignatureChecker implements SignatureCheckerInterface
{
    public function __construct(private Config $config, private JOSEFactory $JOSEFactory)
    {
    }

    public function check(string $token): void
    {
        $jwks = $this->config->getProviderMetadata()->getJwks();
        $this->createJWSLoader()->loadAndVerifyWithKeySet($token, $jwks, $signature);
    }

    private function createJWSLoader(): JWSLoader
    {
        return $this->JOSEFactory->createJWSLoader($this->config);
    }
}
