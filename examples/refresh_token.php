<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\Client\RefreshToken;
use DigitalCz\OpenIDConnect\Client\Tokens;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

require dirname(__DIR__) . '/vendor/autoload.php';

$httpClient = HttpClient::create();
$factory = new OidcFactory($httpClient);

$clientMetadata = new ClientMetadata(
    clientId: 'clientid',
    clientSecret: 'clientsecret',
    redirectUri: 'https://example.com/callback',
);
$oidc = $factory->create('https://samples.auth0.com/', $clientMetadata);
$authorizationCode = $oidc->authorizationCode();

$refreshToken = readline('Enter your refresh token: ');

$tokens = new Tokens(refreshToken: new RefreshToken($refreshToken));

$newTokens = $authorizationCode->refreshToken($tokens);

dump(newTokens: $newTokens);
