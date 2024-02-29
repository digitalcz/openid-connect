<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use Generator;
use Jose\Component\Core\Algorithm;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS384A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;

final class AlgorithmsFactory
{
    /**
     * @var array<string, class-string<Algorithm>>
     */
    private static array $algorithms = [// @phpstan-ignore-line
        'A128CBC-HS256' => A128CBCHS256::class,
        'A128GCM' => A128GCM::class,
        'A128GCMKW' => A128GCMKW::class,
        'A128KW' => A128KW::class,
        'A192CBC-HS384' => A192CBCHS384::class,
        'A192GCM' => A192GCM::class,
        'A192GCMKW' => A192GCMKW::class,
        'A192KW' => A192KW::class,
        'A256CBC-HS512' => A256CBCHS512::class,
        'A256GCM' => A256GCM::class,
        'A256GCMKW' => A256GCMKW::class,
        'A256KW' => A256KW::class,
        'ECDH-ES' => ECDHES::class,
        'ECDH-ES+A128KW' => ECDHESA128KW::class,
        'ECDH-ES+A192KW' => ECDHESA192KW::class,
        'ECDH-ES+A256KW' => ECDHESA256KW::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'OKP' => EdDSA::class,
        'PBES2-HS256+A128KW' => PBES2HS256A128KW::class,
        'PBES2-HS384+A192KW' => PBES2HS384A192KW::class,
        'PBES2-HS512+A256KW' => PBES2HS512A256KW::class,
        'PS256' => PS256::class,
        'PS384' => PS384::class,
        'PS512' => PS512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'RSA-OAEP' => RSAOAEP::class,
        'RSA-OAEP-256' => RSAOAEP256::class,
        'RSA1_5' => RSA15::class,
        'none' => None::class,
        'dir' => Dir::class,
    ];

    /**
     * @return Generator<Algorithm>
     */
    public static function create(): Generator
    {
        foreach (self::$algorithms as $alias => $class) {
            if (class_exists($class)) {
                yield $alias => new $class();
            }
        }
    }
}
