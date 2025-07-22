<?php

declare(strict_types=1);

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

$url = $authorizationCode->createAuthorizationUrl(['state' => 'foo', 'nonce' => 'bar']);

echo "Open the following URL in your browser:" . PHP_EOL;
echo $url . PHP_EOL . PHP_EOL;

$code = readline('Insert the authorization code from the URL: ');

$tokens = $authorizationCode->fetchTokens($code, 'bar');

dump(tokens: $tokens);

$userinfo = $authorizationCode->fetchUserinfo($tokens);

dump(userinfo: $userinfo);
