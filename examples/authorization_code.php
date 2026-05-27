<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

require dirname(__DIR__) . '/vendor/autoload.php';

$httpClient = HttpClient::create();

$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://auth.example.com',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
    redirectUri: 'https://myapp.example.com/callback',
);
$authorizationCode = $oidc->authorizationCode();

// createAuthorizationUrl() auto-generates cryptographically random state, nonce, and PKCE
// code_verifier. In a real web application you must persist these in session before redirecting
// and validate state on the callback to prevent CSRF attacks. See README for a complete example.
$result = $authorizationCode->createAuthorizationUrl();

echo "Open the following URL in your browser:" . PHP_EOL;
echo $result->url() . PHP_EOL . PHP_EOL;

// In a real application:
//   $_SESSION['oauth_state'] = $result->state();
//   $_SESSION['oauth_nonce'] = $result->nonce();
//   $_SESSION['oauth_code_verifier'] = $result->codeVerifier();
//
// On callback, verify state before proceeding:
//   if (!hash_equals($_SESSION['oauth_state'], $_GET['state'])) {
//       throw new RuntimeException('Invalid state - possible CSRF attack.');
//   }

$code = readline('Insert the authorization code from the URL: ');

if ($code === false) {
    throw new RuntimeException('Failed to read authorization code');
}

$tokens = $authorizationCode->fetchTokens(
    code: $code,
    nonce: $result->nonce(),
    codeVerifier: $result->codeVerifier(),
);

dump(tokens: $tokens);

$userinfo = $authorizationCode->fetchUserinfo($tokens);

dump(userinfo: $userinfo);
