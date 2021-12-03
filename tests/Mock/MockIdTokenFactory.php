<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Mock;

use Jose\Component\Core\JWKSet;
use Jose\Easy\Build;
use Jose\Easy\JWSBuilder;

use function Safe\file_get_contents;

final class MockIdTokenFactory
{
    public static function create(): string
    {
        $jwks = JWKSet::createFromJson(file_get_contents(TESTS_DIR . '/Mock/jwks.json'));

        /** @var JWSBuilder $jwsBuilder */
        $jwsBuilder = Build::jws()
            ->exp(time() + 3600)
            ->iat(time())
            ->nbf(time())
            ->jti('12345')
            ->alg('ES256')
            ->iss('https://example.com')
            ->aud('foo')
            ->sub('subject')
            ->claim('foo', 'bar');

        return $jwsBuilder->sign($jwks->get('sign'));
    }
}
