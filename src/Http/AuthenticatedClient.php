<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Http;

use DigitalCz\OpenIDConnect\Client;
use DigitalCz\OpenIDConnect\Token\Tokens;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class AuthenticatedClient implements ClientInterface
{
    public function __construct(
        private readonly Client $client,
        private readonly HttpClient $httpClient,
        private Tokens $tokens
    ) {
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->tokens = $this->client->refreshTokens($this->tokens);

        return $this->httpClient->sendRequest(
            $request->withHeader('Authorization', "Bearer {$this->tokens->accessToken()}")
        );
    }
}
