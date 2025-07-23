<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use Generator;
use Jose\Component\Core\Algorithm;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;

/**
 * JOSE algorithm factory
 */
final class SignatureAlgorithmsFactory
{
    /**
     * @var array<int, class-string<Algorithm>>
     */
    private static array $algorithms = [
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
    ];

    /**
     * Create available signature algorithms
     *
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
