<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

require dirname(__DIR__) . '/vendor/autoload.php';

$httpClient = HttpClient::create();

$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://auth.example.com',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
    // Reject logout tokens without a "sid" claim:
    // backchannelLogoutSessionRequired: true,
);

$handler = $oidc->backChannelLogout();

// In a real scenario this is the "logout_token" form parameter the OP POSTs
// to your registered back-channel logout endpoint.
$logoutToken = readline('Enter logout token: ');

if ($logoutToken === false) {
    throw new RuntimeException('Failed to read logout token');
}

try {
    $token = $handler->handleLogoutRequest($logoutToken);
} catch (InvalidTokenException $e) {
    // Per spec, respond with HTTP 400 on an invalid logout token.
    throw $e;
}

// The application is responsible for:
//  - replay protection: ensure this jti has not been processed recently
//  - session termination: destroy the session(s) for sid and/or sub
dump(
    jti: $token->jti(),
    sub: $token->sub(),
    sid: $token->sid(),
);
