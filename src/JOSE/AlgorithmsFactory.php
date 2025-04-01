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
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
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
     * @var array<int, class-string<Algorithm>>
     */
    private static array $algorithms = [// @phpstan-ignore-line
        A128CBCHS256::class,
        A128GCM::class,
        A192CBCHS384::class,
        A192GCM::class,
        A256CBCHS512::class,
        A256GCM::class,
        ECDHES::class,
        ES256::class,
        ES384::class,
        ES512::class,
        HS256::class,
        HS384::class,
        HS512::class,
        EdDSA::class,
        PS256::class,
        PS384::class,
        PS512::class,
        RS256::class,
        RS384::class,
        RS512::class,
        RSAOAEP::class,
        RSAOAEP256::class,
        RSA15::class,
        None::class,
        Dir::class,
    ];

    /**
     * @return Generator<Algorithm>
     */
    public static function create(): Generator
    {
        foreach (self::$algorithms as $class) {
            if (class_exists($class)) {
                $algorithm = new $class();

                yield $algorithm->name() => $algorithm;
            }
        }
    }
}
