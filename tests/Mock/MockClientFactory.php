<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Mock;

use Http\Message\RequestMatcher\RequestMatcher;
use Http\Mock\Client;
use Http\Mock\Client as MockClient;
use Nyholm\Psr7\Response;

use function Safe\file_get_contents;

final class MockClientFactory
{
    public static function create(): Client
    {
        $mockClient = new MockClient();
        $mockClient->on(
            new RequestMatcher("/.well-known/openid-configuration"),
            new Response(body: file_get_contents(TESTS_DIR . '/Mock/configuration.json')),
        );
        $mockClient->on(
            new RequestMatcher("/.well-known/jwks"),
            new Response(body: file_get_contents(TESTS_DIR . '/Mock/jwks.json')),
        );

        return $mockClient;
    }
}
