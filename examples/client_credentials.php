<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

require dirname(__DIR__) . '/vendor/autoload.php';

$httpClient = HttpClient::create();
$factory = new OidcFactory($httpClient);

$clientMetadata = new ClientMetadata(clientId: 'your-client-id', clientSecret: 'your-client-secret');

$oidc = $factory->create(issuerMetadata: 'https://your-issuer.com', clientMetadata: $clientMetadata);

$clientCredentials = $oidc->clientCredentials();

try {
    $tokens = $clientCredentials->fetchTokens();

    echo "Client Credentials Grant Successful!" . PHP_EOL . PHP_EOL;
    echo "Access Token: " . $tokens->accessToken() . PHP_EOL;
    echo "Token Type: " . $tokens->tokenType() . PHP_EOL;
    echo "Expires In: " . $tokens->expiresIn() . " seconds" . PHP_EOL;
    echo "Scope: " . $tokens->scope() . PHP_EOL;

    if ($tokens->refreshToken()) {
        echo "Refresh Token: " . $tokens->refreshToken() . PHP_EOL;
    }

    echo PHP_EOL . "Full token object:" . PHP_EOL;
    dd($tokens);
} catch (Throwable $e) {
    echo "Error: " . $e->getMessage() . PHP_EOL;
    echo "Details: " . $e->getTraceAsString() . PHP_EOL;
}
