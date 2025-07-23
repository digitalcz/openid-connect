<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

require dirname(__DIR__) . '/vendor/autoload.php';

$httpClient = HttpClient::create();
$factory = new OidcFactory($httpClient);

// Manual issuer metadata configuration (without discovery)
$issuerMetadata = new IssuerMetadata([
    'issuer' => 'https://your-issuer.com',
    'authorization_endpoint' => 'https://your-issuer.com/authorize',
    'token_endpoint' => 'https://your-issuer.com/token',
    'userinfo_endpoint' => 'https://your-issuer.com/userinfo',
    'jwks_uri' => 'https://your-issuer.com/.well-known/jwks.json',
    'response_types_supported' => ['code', 'id_token', 'code id_token'],
    'subject_types_supported' => ['public'],
    'id_token_signing_alg_values_supported' => ['RS256'],
    'scopes_supported' => ['openid', 'profile', 'email'],
    'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic'],
    'claims_supported' => ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'name', 'email'],
]);

$clientMetadata = new ClientMetadata(
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    redirectUri: 'https://your-app.com/callback',
);

// Create OIDC instance with manual configuration
$oidc = $factory->create($issuerMetadata, $clientMetadata);

dump($oidc);
