<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Mock;

use DigitalCz\OpenIDConnect\Util\Json;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use RuntimeException;

use function file_get_contents;

final class MockIdTokenFactory
{
    public static function create(): string
    {
        $jwks = file_get_contents(TESTS_DIR . '/Mock/jwks.json');

        if ($jwks === false) {
            throw new RuntimeException('Failed to read jwks.json');
        }

        $jwkSet = JWKSet::createFromJson($jwks);

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
            ->addSignature($jwkSet->get('sign'), ['alg' => 'ES256'])
            ->build();

        return $serializer->serialize($jws);
    }
}
