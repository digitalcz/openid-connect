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

$resourceServer = $oidc->resourceServer();

// Example token - in real scenario this would come from Authorization header
$tokenString = readline('Enter access token to validate: ');

if (trim($tokenString) === '') {
    echo "No token provided. Exiting." . PHP_EOL;
    exit(1);
}

// Remove "Bearer " prefix if present
if (str_starts_with($tokenString, 'Bearer ')) {
    $tokenString = substr($tokenString, 7);
}

try {
    $validatedToken = $resourceServer->validateAccessToken($tokenString);

    echo "Token Validation Successful!" . PHP_EOL . PHP_EOL;
    echo "Client ID: " . $validatedToken->clientId() . PHP_EOL;
    echo "Subject: " . ($validatedToken->subject() ?? 'N/A') . PHP_EOL;
    echo "Issuer: " . ($validatedToken->issuer() ?? 'N/A') . PHP_EOL;
    echo "Audience: " . implode(', ', $validatedToken->audience()) . PHP_EOL;
    echo "Expires At: " . $validatedToken->expiresAt()->format('Y-m-d H:i:s T') . PHP_EOL;
    echo "Issued At: " . ($validatedToken->issuedAt()?->format('Y-m-d H:i:s T') ?? 'N/A') . PHP_EOL;
    echo "Not Before: " . ($validatedToken->notBefore()?->format('Y-m-d H:i:s T') ?? 'N/A') . PHP_EOL;
    echo "Scope: " . ($validatedToken->scope() ?? 'N/A') . PHP_EOL;

    echo PHP_EOL . "All claims:" . PHP_EOL;
    dd($validatedToken->claims());
} catch (Throwable $e) {
    echo "Token validation failed!" . PHP_EOL;
    echo "Error: " . $e->getMessage() . PHP_EOL;
    echo "Details: " . $e->getTraceAsString() . PHP_EOL;
    exit(1);
}
