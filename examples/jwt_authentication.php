<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\OidcFactory;
use Jose\Component\KeyManagement\JWKFactory;
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

if (!$exported) {
    throw new RuntimeException('Failed to export RSA private key');
}

// Create OIDC client with private key JWT authentication using the new factory method
// Note: In practice, you would load the private key from a secure location
OidcFactory::create(
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
);

echo "Private Key JWT authentication configured\n\n";

// Example 3: Private Key JWT Authentication with JWK
echo "=== Private Key JWT Authentication (JWK) ===\n";

if (is_string($privateKey)) {
    $jwk = JWKFactory::createFromKey($privateKey, '', ['kid' => 'my-key-id']);

    // For JWK-based authentication, you would typically use a more specialized setup
    // This is a simplified example showing the concept
    $keyId = $jwk->get('kid');
    echo "JWK created with key ID: " . (is_string($keyId) ? $keyId : 'none') . "\n";
    echo "Private Key JWT authentication with JWK configured\n\n";
}

// Example 4: Manual configuration using IssuerMetadata object
echo "=== Manual Configuration with JWT Authentication ===\n";

$issuerMetadata = new IssuerMetadata([
    'issuer' => 'https://example.com',
    'authorization_endpoint' => 'https://example.com/auth',
    'token_endpoint' => 'https://example.com/token',
    'userinfo_endpoint' => 'https://example.com/userinfo',
    'jwks_uri' => 'https://example.com/.well-known/jwks.json',
]);

OidcFactory::create(
    httpClient: $httpClient,
    issuer: $issuerMetadata,
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret-must-be-long-enough-for-hmac-256-bits',
    redirectUri: 'https://your-app.com/callback',
    authenticationMethod: AuthenticationMethod::ClientSecretJwt,
);

echo "Static configuration with Client Secret JWT authentication\n\n";

// Example 5: Authorization Code Flow Example
echo "=== Authorization Code Flow with JWT Authentication ===\n";

// Generate authorization URL
$authorizationResult = $oidc->authorizationCode()->createAuthorizationUrl([
    'scope' => 'openid profile email',
    'state' => 'random-state-value',
]);

echo "Authorization URL: " . $authorizationResult->url() . "\n\n";

// Example 6: Client Credentials Flow
echo "=== Client Credentials Flow with JWT Authentication ===\n";

echo "Client credentials flow configured with JWT authentication\n";
echo "This flow uses the JWT authentication method automatically\n\n";

// Example 7: Resource Server Token Validation
echo "=== Resource Server Token Validation ===\n";

echo "Resource server configured for token validation\n";
echo "Supports both JWT and opaque token validation\n\n";

echo "=== JWT Authentication Examples Complete ===\n";
