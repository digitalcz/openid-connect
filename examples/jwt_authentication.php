<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

/**
 * Example demonstrating JWT-based client authentication methods
 */

$httpClient = HttpClient::create();

// Example 1: Client Secret JWT Authentication
echo "=== Client Secret JWT Authentication ===\n";

$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://example.com',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret-must-be-long-enough-for-hmac-256-bits',
    redirectUri: 'https://your-app.com/callback',
    authenticationMethod: AuthenticationMethod::ClientSecretJwt,
);

dump($oidc);

echo "Client Secret JWT authentication configured\n\n";

// Example 2: Private Key JWT Authentication with RSA key
echo "=== Private Key JWT Authentication (RSA) ===\n";

// Generate RSA private key for demonstration
$keyResource = openssl_pkey_new([
    'digest_alg' => 'sha256',
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
]);

if ($keyResource === false) {
    throw new RuntimeException('Failed to generate RSA key');
}

$exported = openssl_pkey_export($keyResource, $privateKey);

if (!$exported || !is_string($privateKey)) {
    throw new RuntimeException('Failed to export RSA private key');
}

// Create OIDC client with private key JWT authentication using the new factory method
// Note: In practice, you would load the private key from a secure location
$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: [
        'issuer' => 'https://example.com',
        'authorization_endpoint' => 'https://example.com/auth',
        'token_endpoint' => 'https://example.com/token',
        'userinfo_endpoint' => 'https://example.com/userinfo',
        'jwks_uri' => 'https://example.com/.well-known/jwks.json',
    ],
    clientId: 'your-client-id',
    redirectUri: 'https://your-app.com/callback',
    authenticationMethod: AuthenticationMethod::PrivateKeyJwt,
    privateKey: $privateKey,
);

echo "Private Key JWT authentication configured\n";

dump($oidc);
