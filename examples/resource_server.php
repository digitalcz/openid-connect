<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\OidcFactory;
use DigitalCz\OpenIDConnect\ResourceServer\JwtAccessToken;
use DigitalCz\OpenIDConnect\ResourceServer\OpaqueAccessToken;
use DigitalCz\OpenIDConnect\Util\JWT;
use Symfony\Component\HttpClient\HttpClient;

require dirname(__DIR__) . '/vendor/autoload.php';

$httpClient = HttpClient::create();

$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://auth.example.com',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
);

$resourceServer = $oidc->resourceServer();

// Example token - in real scenario this would come from Authorization header
$token = readline('Enter access token to validate: ');

if ($token === false) {
    throw new RuntimeException('Failed to read access token');
}

$accessToken = JWT::validate($token) ? new JwtAccessToken($token) : new OpaqueAccessToken($token);

$validatedToken = $resourceServer->introspect($accessToken);

dump(validatedToken: $validatedToken);
