<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\Client\Tokens;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

require dirname(__DIR__) . '/vendor/autoload.php';

$httpClient = HttpClient::create();
$factory = new OidcFactory($httpClient);

$clientMetadata = new ClientMetadata(
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    redirectUri: 'https://your-app.com/callback',
);

$oidc = $factory->create(issuerMetadata: 'https://your-issuer.com', clientMetadata: $clientMetadata);

$authorizationCode = $oidc->authorizationCode();

echo "=== Refresh Token Example ===" . PHP_EOL . PHP_EOL;

// First, simulate getting initial tokens (you would normally get these from authorization flow)
echo "For this example, you need existing tokens with a refresh token." . PHP_EOL;
echo "You can get them by first running the authorization_code.php example." . PHP_EOL . PHP_EOL;

$refreshTokenString = readline('Enter your refresh token: ');

if (trim($refreshTokenString) === '') {
    echo "No refresh token provided. Exiting." . PHP_EOL;
    exit(1);
}

// Create a Tokens object with just the refresh token for demonstration
// In real scenario, you would have the full tokens object from previous authorization
$accessTokenString = readline('Enter your current access token (for Tokens object): ');
$idTokenString = readline('Enter your ID token (or press Enter to skip): ');

try {
    // Create a tokens object with the provided tokens
    $currentTokens = new Tokens(
        accessToken: $accessTokenString ?: 'dummy-access-token',
        tokenType: 'Bearer',
        expiresIn: 3600,
        refreshToken: $refreshTokenString,
        scope: 'openid profile email',
        idToken: trim($idTokenString) !== '' ? $idTokenString : null,
    );

    echo PHP_EOL . "Refreshing tokens..." . PHP_EOL;

    $newTokens = $authorizationCode->refreshToken($currentTokens);

    echo "Tokens refreshed successfully!" . PHP_EOL . PHP_EOL;
    echo "New Access Token: " . $newTokens->accessToken() . PHP_EOL;
    echo "New Token Type: " . $newTokens->tokenType() . PHP_EOL;
    echo "New Expires In: " . $newTokens->expiresIn() . " seconds" . PHP_EOL;
    echo "New Refresh Token: " . ($newTokens->refreshToken() ?? 'Same as before (not rotated)') . PHP_EOL;
    echo "New Scope: " . ($newTokens->scope() ?? 'N/A') . PHP_EOL;

    if ($newTokens->idToken()) {
        echo "New ID Token: " . $newTokens->idToken() . PHP_EOL;
    }

    echo PHP_EOL . "Full new tokens object:" . PHP_EOL;
    dd($newTokens);
} catch (Throwable $e) {
    echo "Token refresh failed!" . PHP_EOL;
    echo "Error: " . $e->getMessage() . PHP_EOL;
    echo "Details: " . $e->getTraceAsString() . PHP_EOL;
    exit(1);
}
