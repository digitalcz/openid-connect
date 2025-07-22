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

echo "=== Userinfo Endpoint Example ===" . PHP_EOL . PHP_EOL;

echo "This example shows how to fetch user information using the userinfo endpoint." . PHP_EOL;
echo "You need valid tokens from an authorization flow." . PHP_EOL . PHP_EOL;

$accessTokenString = readline('Enter your access token: ');

if (trim($accessTokenString) === '') {
    echo "No access token provided. Exiting." . PHP_EOL;
    exit(1);
}

$idTokenString = readline('Enter your ID token (optional, press Enter to skip): ');

try {
    // Create a tokens object with the provided tokens
    $tokens = new Tokens(
        accessToken: $accessTokenString,
        tokenType: 'Bearer',
        expiresIn: 3600,
        refreshToken: null,
        scope: 'openid profile email',
        idToken: trim($idTokenString) !== '' ? $idTokenString : null,
    );

    echo PHP_EOL . "Fetching user information..." . PHP_EOL;

    $userinfo = $authorizationCode->fetchUserinfo($tokens);

    echo "User information retrieved successfully!" . PHP_EOL . PHP_EOL;

    echo "Subject (sub): " . $userinfo->sub() . PHP_EOL;
    echo "Name: " . ($userinfo->name() ?? 'N/A') . PHP_EOL;
    echo "Given Name: " . ($userinfo->givenName() ?? 'N/A') . PHP_EOL;
    echo "Family Name: " . ($userinfo->familyName() ?? 'N/A') . PHP_EOL;
    echo "Email: " . ($userinfo->email() ?? 'N/A') . PHP_EOL;
    echo "Email Verified: " . ($userinfo->emailVerified() ? 'Yes' : 'No') . PHP_EOL;
    echo "Picture: " . ($userinfo->picture() ?? 'N/A') . PHP_EOL;
    echo "Locale: " . ($userinfo->locale() ?? 'N/A') . PHP_EOL;
    echo "Updated At: " . ($userinfo->updatedAt()?->format('Y-m-d H:i:s T') ?? 'N/A') . PHP_EOL;

    echo PHP_EOL . "All userinfo claims:" . PHP_EOL;
    dd($userinfo->claims());
} catch (Throwable $e) {
    echo "Failed to fetch userinfo!" . PHP_EOL;
    echo "Error: " . $e->getMessage() . PHP_EOL;
    echo "Details: " . $e->getTraceAsString() . PHP_EOL;
    exit(1);
}
