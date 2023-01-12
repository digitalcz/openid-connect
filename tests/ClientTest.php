<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Exception\AuthorizationException;
use DigitalCz\OpenIDConnect\Grant\ClientCredentials;
use DigitalCz\OpenIDConnect\Http\HttpClientFactory;
use DigitalCz\OpenIDConnect\Mock\MockClientFactory;
use DigitalCz\OpenIDConnect\Mock\MockIdTokenFactory;
use DigitalCz\OpenIDConnect\Param\AuthorizationParams;
use DigitalCz\OpenIDConnect\Param\CallbackChecks;
use DigitalCz\OpenIDConnect\Param\CallbackParams;
use DigitalCz\OpenIDConnect\Param\TokenParams;
use DigitalCz\OpenIDConnect\Util\Json;
use DigitalCz\OpenIDConnect\Util\JWT;
use Http\Message\RequestMatcher\RequestMatcher;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * @covers \DigitalCz\OpenIDConnect\Client
 */
class ClientTest extends TestCase
{
    public function testGetAuthorizationUrl(): void
    {
        $client = ClientFactory::create(
            'https://example.com/.well-known/openid-configuration',
            new ClientMetadata('foo', 'bar', 'https://example.com/callback'),
            HttpClientFactory::create(MockClientFactory::create()),
        );

        $url = $client->getAuthorizationUrl(
            new AuthorizationParams(['scope' => 'openid profile', 'state' => 'bar', 'nonce' => 'moo']),
        );

        self::assertSame('example.com', $url->getHost());
        self::assertSame('https', $url->getScheme());
        parse_str($url->getQuery(), $queryParams);
        self::assertSame('openid profile', $queryParams['scope']);
        self::assertSame('code', $queryParams['response_type']);
        self::assertSame('https://example.com/callback', $queryParams['redirect_uri']);
        self::assertSame('foo', $queryParams['client_id']);
        self::assertSame('bar', $queryParams['state']);
        self::assertSame('moo', $queryParams['nonce']);
    }

    public function testHandleCallback(): void
    {
        $idToken = MockIdTokenFactory::create();
        $mockClient = MockClientFactory::create();
        $mockClient->on(
            new RequestMatcher('/token'),
            new Response(body: Json::encode([
                'access_token' => 'foo_token',
                'refresh_token' => 'bar_token',
                'id_token' => $idToken,
            ])),
        );

        $client = ClientFactory::create(
            'https://example.com/.well-known/openid-configuration',
            new ClientMetadata('foo', 'bar', 'https://example.com/callback'),
            HttpClientFactory::create($mockClient),
        );

        $tokens = $client->handleCallback(
            new CallbackParams(['state' => 'foo', 'code' => 'bar']),
            new CallbackChecks('foo'),
        );

        self::assertSame('foo_token', $tokens->accessToken());
        self::assertSame('bar_token', $tokens->refreshToken());
        self::assertSame($idToken, $tokens->idToken());
        self::assertSame('bar', JWT::claim($tokens->idToken(), 'foo'));

        $authenticatedClient = $client->getAuthenticatedClient($tokens);
        $authenticatedClient->sendRequest(new Request('GET', 'https://example.com'));

        self::assertSame(
            'Bearer foo_token',
            $mockClient->getLastRequest()->getHeaderLine('Authorization'),
        );
    }

    public function testHandleCallbackWithError(): void
    {
        $client = ClientFactory::create(
            'https://example.com/.well-known/openid-configuration',
            new ClientMetadata('foo', 'bar', 'https://example.com/callback'),
            HttpClientFactory::create(MockClientFactory::create()),
        );

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('Foo: bar');

        $client->handleCallback(
            new CallbackParams(['error' => 'Foo', 'error_description' => 'bar']),
            new CallbackChecks(),
        );
    }

    public function testHandleCallbackWithStateMismatch(): void
    {
        $client = ClientFactory::create(
            'https://example.com/.well-known/openid-configuration',
            new ClientMetadata('foo', 'bar', 'https://example.com/callback'),
            HttpClientFactory::create(MockClientFactory::create()),
        );

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('State mismatch, expected: bar, got foo');

        $client->handleCallback(
            new CallbackParams(['state' => 'foo']),
            new CallbackChecks('bar'),
        );
    }

    public function testRequestTokensWithClientCredentials(): void
    {
        $mockClient = MockClientFactory::create();
        $mockClient->on(
            new RequestMatcher('/token'),
            new Response(body: Json::encode([
                'access_token' => 'foo_token',
                'refresh_token' => 'bar_token',
            ])),
        );

        $client = ClientFactory::create(
            'https://example.com/.well-known/openid-configuration',
            new ClientMetadata('foo', 'bar', 'https://example.com/callback'),
            HttpClientFactory::create($mockClient),
        );
        $tokens = $client->requestTokens(new TokenParams(new ClientCredentials(), ['scope' => 'all']));

        self::assertSame('foo_token', $tokens->accessToken());
        self::assertSame('bar_token', $tokens->refreshToken());

        $lastRequest = $mockClient->getLastRequest();
        self::assertSame('POST', $lastRequest->getMethod());
        self::assertSame('example.com', $lastRequest->getUri()->getHost());
        self::assertSame('/token', $lastRequest->getUri()->getPath());
        self::assertSame('application/x-www-form-urlencoded', $lastRequest->getHeaderLine('content-type'));
        parse_str((string)$lastRequest->getBody(), $body);
        $expectedBody = [
            'scope' => 'all',
            'grant_type' => 'client_credentials',
            'client_id' => 'foo',
            'client_secret' => 'bar',
        ];
        self::assertSame($expectedBody, $body);
    }

    public function testRequestTokensError(): void
    {
        $mockClient = MockClientFactory::create();
        $mockClient->on(
            new RequestMatcher('/token'),
            new Response(status: 404, body: 'Not Found'),
        );
        $client = ClientFactory::create(
            'https://example.com/.well-known/openid-configuration',
            new ClientMetadata('foo', 'bar', 'https://example.com/callback'),
            HttpClientFactory::create($mockClient),
        );

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('Token request error: 404 Not Found returned for POST https://example.com/token');
        $client->requestTokens(new TokenParams(new ClientCredentials(), ['scope' => 'all']));
    }

    public function testRequestTokensInvalidResponse(): void
    {
        $mockClient = MockClientFactory::create();
        $mockClient->on(
            new RequestMatcher('/token'),
            new Response(body: '{not a: json]'),
        );
        $client = ClientFactory::create(
            'https://example.com/.well-known/openid-configuration',
            new ClientMetadata('foo', 'bar', 'https://example.com/callback'),
            HttpClientFactory::create($mockClient),
        );

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('Invalid response from token endpoint: Unable to parse response: Syntax error');
        $client->requestTokens(new TokenParams(new ClientCredentials(), ['scope' => 'all']));
    }
}
