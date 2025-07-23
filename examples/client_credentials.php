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
$clientCredentials = $oidc->clientCredentials();

$tokens = $clientCredentials->fetchTokens();

dump(tokens: $tokens);
