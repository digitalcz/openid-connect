<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\OidcFactory;
use DigitalCz\OpenIDConnect\ResourceServer\JwtAccessToken;
use DigitalCz\OpenIDConnect\ResourceServer\OpaqueAccessToken;
use DigitalCz\OpenIDConnect\Util\JWT;
use Symfony\Component\HttpClient\HttpClient;

require dirname(__DIR__) . '/vendor/autoload.php';

$httpClient = HttpClient::create();
$factory = new OidcFactory($httpClient);

$clientMetadata = new ClientMetadata(clientId: 'your-client-id', clientSecret: 'your-client-secret');

$oidc = $factory->create('https://your-issuer.com', $clientMetadata);

$resourceServer = $oidc->resourceServer();

// Example token - in real scenario this would come from Authorization header
$token = readline('Enter access token to validate: ');

$accessToken = JWT::validate($token) ? new JwtAccessToken($token) : new OpaqueAccessToken($token);

$validatedToken = $resourceServer->introspect($accessToken);

dump(validatedToken: $validatedToken);
