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
$clientCredentials = $oidc->clientCredentials();

$tokens = $clientCredentials->fetchTokens();

dump(tokens: $tokens);
