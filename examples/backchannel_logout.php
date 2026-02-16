<?php

/**
 * Example: Back-Channel Logout
 *
 * This example demonstrates how to handle OpenID Connect Back-Channel Logout requests.
 * Back-Channel Logout allows the OpenID Provider to notify Relying Parties when a user
 * has logged out, enabling secure session termination across all applications.
 *
 * SECURITY CONSIDERATIONS:
 * 1. Implement rate limiting on this endpoint to prevent DoS attacks
 * 2. Implement replay attack prevention by tracking processed JTIs
 * 3. Ensure the endpoint responds quickly (< 100ms) as OPs may have timeouts
 * 4. Use HTTPS in production to protect the logout token in transit
 *
 * phpcs:disable PSR1.Files.SideEffects.FoundWithSymbols
 * phpcs:disable Squiz.NamingConventions.ValidVariableName.NotCamelCaps
 */

declare(strict_types=1);

use DigitalCz\OpenIDConnect\Exception\InvalidLogoutTokenException;
use DigitalCz\OpenIDConnect\Exception\LogoutTokenExpiredException;
use DigitalCz\OpenIDConnect\Exception\UntrustedLogoutTokenException;
use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

require __DIR__ . '/../vendor/autoload.php';

// Simulate getting logout token from request (in production, use proper request handling)
// phpcs:disable SlevomatCodingStandard.Variables.DisallowSuperGlobalVariable
$logoutTokenString = $_POST['logout_token'] ?? null;
// phpcs:enable SlevomatCodingStandard.Variables.DisallowSuperGlobalVariable

if ($logoutTokenString === null || $logoutTokenString === '') {
    http_response_code(400);
    echo "Missing logout_token parameter\n";

    exit;
}

// Create OIDC client with back-channel logout configuration
$oidc = OidcFactory::create(
    httpClient: HttpClient::create(),
    issuer: 'https://auth.example.com',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
    backchannelLogoutUri: 'https://myapp.example.com/logout/backchannel',
    backchannelLogoutSessionRequired: true,
);

try {
    // Validate the logout token
    $logoutToken = $oidc->backChannelLogout()->handleLogoutRequest($logoutTokenString);

    // IMPORTANT: Implement replay attack prevention
    // Track processed JTIs to prevent replay attacks:
    // if (hasProcessedJti($logoutToken->jwtId())) { /* reject */ }
    // markJtiAsProcessed($logoutToken->jwtId(), $logoutToken->issuedAt() + 3600);

    $subject = $logoutToken->subject();
    $sessionId = $logoutToken->sessionId();
    $issuer = $logoutToken->issuer();

    echo "Received valid logout token from: {$issuer}\n";

    if ($subject !== null && $sessionId !== null) {
        echo "Terminating session '{$sessionId}' for user '{$subject}'\n";
        terminateUserSession($subject, $sessionId);
    } elseif ($subject !== null) {
        echo "Terminating all sessions for user '{$subject}'\n";
        terminateAllUserSessions($subject);
    } elseif ($sessionId !== null) {
        echo "Terminating session '{$sessionId}'\n";
        terminateSession($sessionId);
    }

    http_response_code(200);
    echo "Logout processed successfully\n";
} catch (InvalidLogoutTokenException $e) {
    http_response_code(400);
    echo "Invalid logout token: " . $e->getMessage() . "\n";
} catch (UntrustedLogoutTokenException $e) {
    http_response_code(403);
    echo "Untrusted logout token: " . $e->getMessage() . "\n";
} catch (LogoutTokenExpiredException $e) {
    http_response_code(410);
    echo "Logout token expired: " . $e->getMessage() . "\n";
}

/**
 * Terminate specific user session
 *
 * @param string $userId    User identifier
 * @param string $sessionId Session identifier
 */
function terminateUserSession(string $userId, string $sessionId): void
{
    // Implementation: Delete session from store, invalidate refresh tokens
    echo "  → Session terminated\n";
}

/**
 * Terminate all sessions for a user
 *
 * @param string $userId User identifier
 */
function terminateAllUserSessions(string $userId): void
{
    // Implementation: Delete all user sessions, invalidate all refresh tokens
    echo "  → All user sessions terminated\n";
}

/**
 * Terminate session by ID
 *
 * @param string $sessionId Session identifier
 */
function terminateSession(string $sessionId): void
{
    // Implementation: Delete session from store, invalidate refresh tokens
    echo "  → Session terminated\n";
}
