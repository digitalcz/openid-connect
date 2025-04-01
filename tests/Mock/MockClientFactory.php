<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Mock;

use Http\Message\RequestMatcher\RequestMatcher;
use Http\Mock\Client;
use Http\Mock\Client as MockClient;
use Nyholm\Psr7\Response;
use RuntimeException;

use function file_get_contents;

final class MockClientFactory
{
    public static function create(): Client
    {
        $mockClient = new MockClient();
        $configuration = file_get_contents(TESTS_DIR . '/Mock/configuration.json');

        if ($configuration === false) {
            throw new RuntimeException('Failed to read configuration.json');
        }

        $jwks = file_get_contents(TESTS_DIR . '/Mock/jwks.json');

        if ($jwks === false) {
            throw new RuntimeException('Failed to read jwks.json');
        }

        $mockClient->on(
            new RequestMatcher("/.well-known/openid-configuration"),
            new Response(body: $configuration),
        );
        $mockClient->on(
            new RequestMatcher("/.well-known/jwks"),
            new Response(body: $jwks),
        );

        return $mockClient;
    }
}
