<?php

declare(strict_types=1);

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

$url = $authorizationCode->createAuthorizationUrl(['state' => 'foo', 'nonce' => 'bar']);

echo "Open the following URL in your browser:" . PHP_EOL;
echo $url . PHP_EOL . PHP_EOL;

$code = readline('Insert the authorization code from the URL: ');

$tokens = $authorizationCode->fetchTokens($code, 'bar');

dump(tokens: $tokens);

$userinfo = $authorizationCode->fetchUserinfo($tokens);

dump(userinfo: $userinfo);
