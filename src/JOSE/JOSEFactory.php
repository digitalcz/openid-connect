<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use DigitalCz\OpenIDConnect\Config;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES256K;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS1;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS256_64;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS1;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\Util\RSA;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

final class JOSEFactory
{
    private AlgorithmManagerFactory $algorithmManagerFactory;

    public function __construct()
    {
        $this->algorithmManagerFactory = new AlgorithmManagerFactory();
        foreach (AlgorithmsFactory::create() as $alias => $algorithm) {
            $this->algorithmManagerFactory->add($alias, $algorithm);
        }
    }

    public function createJWSLoader(Config $config): JWSLoader
    {
        $algorithms = $this->resolveAlgorithms($config);

        return new JWSLoader(
            new JWSSerializerManager([new CompactSerializer()]),
            new JWSVerifier($this->algorithmManagerFactory->create($algorithms)),
            new HeaderCheckerManager([new AlgorithmChecker($algorithms)], [new JWSTokenSupport()])
        );
    }

    /** @return string[] */
    private function resolveAlgorithms(Config $config): array
    {
        $providerMetadata = $config->getProviderMetadata();

        return array_unique(
            array_merge(
                $providerMetadata->idTokenSigningAlgValuesSupported(),
                $providerMetadata->idTokenEncryptionAlgValuesSupported(),
                $providerMetadata->idTokenEncryptionEncValuesSupported()
            )
        );
    }
}
