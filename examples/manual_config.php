<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\Client\AuthorizationCode;
use DigitalCz\OpenIDConnect\Client\ClientCredentials;
use DigitalCz\OpenIDConnect\Client\JwtIdTokenValidator;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Config\StaticConfig;
use DigitalCz\OpenIDConnect\Discovery\HttpJwksLoader;
use DigitalCz\OpenIDConnect\Oidc;
use DigitalCz\OpenIDConnect\ResourceServer\JwtAccessTokenValidator;
use DigitalCz\OpenIDConnect\ResourceServer\ResourceServer;
use DigitalCz\OpenIDConnect\Util\PkceMethod;
use Symfony\Component\HttpClient\HttpClient;

require dirname(__DIR__) . '/vendor/autoload.php';

$httpClient = HttpClient::create();

// Manual issuer metadata configuration (without discovery)
$issuerMetadata = new IssuerMetadata([
    'issuer' => 'https://auth.example.com',
    'authorization_endpoint' => 'https://auth.example.com/authorize',
    'token_endpoint' => 'https://auth.example.com/token',
    'userinfo_endpoint' => 'https://auth.example.com/userinfo',
    'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
    'response_types_supported' => ['code', 'id_token', 'code id_token'],
    'subject_types_supported' => ['public'],
    'id_token_signing_alg_values_supported' => ['RS256'],
    'scopes_supported' => ['openid', 'profile', 'email'],
    'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic'],
    'claims_supported' => ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'name', 'email'],
]);

// Manual client metadata configuration
$clientMetadata = new ClientMetadata(
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
    redirectUri: 'https://myapp.example.com/callback',
    defaultScopes: ['openid', 'profile', 'email'],
    authenticationMethod: AuthenticationMethod::ClientSecretPost,
    pkceMethod: PkceMethod::S256,
);

// Create configuration without discovery
$config = new StaticConfig($issuerMetadata, $clientMetadata);

// Create JWKS loader for JWT validation
$jwksLoader = new HttpJwksLoader($httpClient);

// Create ID token validator
$idTokenValidator = new JwtIdTokenValidator($config, $jwksLoader);

// Create authorization code flow handler
$authorizationCode = new AuthorizationCode($config, $httpClient, $idTokenValidator);

// Create client credentials flow handler
$clientCredentials = new ClientCredentials($config, $httpClient);

// Create access token validators for resource server
$jwtAccessTokenValidator = new JwtAccessTokenValidator(
    $config,
    $jwksLoader,
    $clientMetadata->clientId(),
);

// Optionally, you can also use an opaque access token validator
$resourceServer = new ResourceServer([$jwtAccessTokenValidator]);

// Create OIDC instance manually
$oidc = new Oidc($authorizationCode, $clientCredentials, $resourceServer);

dump($oidc);
