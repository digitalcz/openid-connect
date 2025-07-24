<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\Client\RefreshToken;
use DigitalCz\OpenIDConnect\Client\Tokens;
use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

require dirname(__DIR__) . '/vendor/autoload.php';

$httpClient = HttpClient::create();

$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://auth.example.com',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
    redirectUri: 'https://myapp.example.com/callback',
);
$authorizationCode = $oidc->authorizationCode();

$refreshToken = readline('Enter your refresh token: ');

if ($refreshToken === false) {
    throw new RuntimeException('Failed to read refresh token');
}

$tokens = new Tokens(refreshToken: new RefreshToken($refreshToken));

$newTokens = $authorizationCode->refreshToken($tokens);

dump(newTokens: $newTokens);
