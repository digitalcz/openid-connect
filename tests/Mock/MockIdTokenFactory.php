<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Mock;

use DigitalCz\OpenIDConnect\Util\Json;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

use function Safe\file_get_contents;

final class MockIdTokenFactory
{
    public static function create(): string
    {
        $jwks = JWKSet::createFromJson(file_get_contents(TESTS_DIR . '/Mock/jwks.json'));

        $algorithmManager = new AlgorithmManager([new ES256()]);
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $serializer = new CompactSerializer();

        $jws = $jwsBuilder->create()
            ->withPayload(Json::encode([
                'exp' => time() + 3600,
                'iat' => time(),
                'nbf' => time(),
                'jti' => '12345',
                'iss' => 'https://example.com',
                'aud' => 'foo',
                'sub' => 'subject',
                'foo' => 'bar',
            ]))
            ->addSignature($jwks->get('sign'), ['alg' => 'ES256'])
            ->build();

        return $serializer->serialize($jws);
    }
}
