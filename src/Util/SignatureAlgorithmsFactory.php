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
     * Symmetric (HMAC) signature algorithms.
     *
     * @var array<int, class-string<Algorithm>>
     */
    private static array $symmetricAlgorithms = [
        HS256::class,
        HS384::class,
        HS512::class,
    ];

    /**
     * Asymmetric (public-key) signature algorithms.
     *
     * @var array<int, class-string<Algorithm>>
     */
    private static array $asymmetricAlgorithms = [
        ES256::class,
        ES384::class,
        ES512::class,
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
        foreach ([...self::$symmetricAlgorithms, ...self::$asymmetricAlgorithms] as $class) {
            if (class_exists($class)) {
                $algorithm = new $class();

                yield $algorithm->name() => $algorithm;
            }
        }
    }

    /**
     * Names of the available asymmetric (public-key) signature algorithms.
     *
     * Verification of tokens against a provider JWKS must be restricted to these,
     * never accepting HMAC, per RFC 8725 §3.1 — defense-in-depth against
     * algorithm-confusion attacks.
     *
     * @return list<string>
     *
     * @see https://www.rfc-editor.org/rfc/rfc8725#section-3.1
     */
    public static function asymmetricAlgorithmNames(): array
    {
        $names = [];

        foreach (self::$asymmetricAlgorithms as $class) {
            if (class_exists($class)) {
                $names[] = (new $class())->name();
            }
        }

        return $names;
    }
}
