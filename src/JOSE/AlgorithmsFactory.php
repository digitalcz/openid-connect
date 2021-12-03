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
use Jose\Component\Signature\Algorithm\ES256K;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS1;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS256_64;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS1;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;

final class AlgorithmsFactory
{
    /**
     * @return Generator<Algorithm>
     */
    public static function create(): Generator
    {
        yield 'ES256' => new ES256();
        yield 'ES256K' => new ES256K();
        yield 'ES384' => new ES384();
        yield 'ES512' => new ES512();
        yield 'HS1' => new HS1();
        yield 'HS256' => new HS256();
        yield 'HS256/64' => new HS256_64();
        yield 'HS384' => new HS384();
        yield 'HS512' => new HS512();
        yield 'OKP' => new EdDSA();
        yield 'PS256' => new PS256();
        yield 'PS384' => new PS384();
        yield 'PS512' => new PS512();
        yield 'RS1' => new RS1();
        yield 'RS256' => new RS256();
        yield 'RS384' => new RS384();
        yield 'RS512' => new RS512();
        yield 'none' => new None();
        yield 'RSA1_5' => new RSA15();
        yield 'RSA-OAEP' => new RSAOAEP();
        yield 'RSA-OAEP-256' => new RSAOAEP256();
        yield 'A128KW' => new A128KW();
        yield 'A192KW' => new A192KW();
        yield 'A256KW' => new A256KW();
        yield 'ECDH-ES' => new ECDHES();
        yield 'ECDH-ES+A128KW' => new ECDHESA128KW();
        yield 'ECDH-ES+A192KW' => new ECDHESA192KW();
        yield 'ECDH-ES+A256KW' => new ECDHESA256KW();
        yield 'A128GCMKW' => new A128GCMKW();
        yield 'A192GCMKW' => new A192GCMKW();
        yield 'A256GCMKW' => new A256GCMKW();
        yield 'PBES2-HS256+A128KW' => new PBES2HS256A128KW();
        yield 'PBES2-HS384+A192KW' => new PBES2HS384A192KW();
        yield 'PBES2-HS512+A256KW' => new PBES2HS512A256KW();
        yield 'A128CBC-HS256' => new A128CBCHS256();
        yield 'A192CBC-HS384' => new A192CBCHS384();
        yield 'A256CBC-HS512' => new A256CBCHS512();
        yield 'A128GCM' => new A128GCM();
        yield 'A192GCM' => new A192GCM();
        yield 'A256GCM' => new A256GCM();
    }
}
