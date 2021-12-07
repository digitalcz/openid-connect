<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Http;

use DigitalCz\OpenIDConnect\Client;
use DigitalCz\OpenIDConnect\Grant\RefreshToken;
use DigitalCz\OpenIDConnect\Param\TokenParams;
use DigitalCz\OpenIDConnect\Token\Tokens;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class AuthenticatedClient implements ClientInterface
{
    public function __construct(private Client $client, private Tokens $tokens)
    {
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $tokens = $this->tokens;

        if ($tokens->isExpired() && $tokens->getRefreshToken() !== null) {
            $tokenParams = new TokenParams(new RefreshToken(), ['refresh_token' => $tokens->getRefreshToken()]);
            $this->tokens = $this->client->requestTokens($tokenParams);
        }

        return $this->client->sendRequest(
            $request->withHeader('Authorization', "Bearer {$tokens->getAccessToken()}")
        );
    }

    public function getTokens(): Tokens
    {
        return $this->tokens;
    }
}
