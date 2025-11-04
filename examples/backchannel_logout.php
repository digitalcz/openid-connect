<?php

declare(strict_types=1);

/**
 * Example: Back-Channel Logout
 *
 * This example demonstrates how to handle OpenID Connect Back-Channel Logout requests.
 * Back-Channel Logout allows the OpenID Provider to notify Relying Parties when a user
 * has logged out, enabling secure session termination across all applications.
 */

use DigitalCz\OpenIDConnect\Exception\InvalidLogoutTokenException;
use DigitalCz\OpenIDConnect\Exception\LogoutTokenExpiredException;
use DigitalCz\OpenIDConnect\Exception\UntrustedLogoutTokenException;
use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

require __DIR__ . '/../vendor/autoload.php';

$httpClient = HttpClient::create();

// Create OIDC client with back-channel logout configuration
$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://auth.example.com',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
    backchannelLogoutUri: 'https://myapp.example.com/logout/backchannel',
    backchannelLogoutSessionRequired: true, // Require 'sid' in logout tokens
);

// Get the back-channel logout handler
$logoutHandler = $oidc->backChannelLogout();

// This would typically be called from your logout endpoint that receives POST requests from the OP
// Example: POST https://myapp.example.com/logout/backchannel
//
// The OpenID Provider sends the logout token in the 'logout_token' parameter:
// $_POST['logout_token'] = 'eyJhbGci...'

// For this example, we'll simulate a logout token (in production, this comes from $_POST)
$logoutTokenString = $_POST['logout_token'] ?? '';

if (empty($logoutTokenString)) {
    http_response_code(400);
    echo "Missing logout_token parameter\n";
    exit;
}

try {
    // Validate the logout token
    $logoutToken = $logoutHandler->handleLogoutRequest($logoutTokenString);

    // Logout token is valid - now terminate user sessions
    // You can access logout token claims to identify which sessions to terminate:

    $subject = $logoutToken->subject();      // User ID (may be null)
    $sessionId = $logoutToken->sessionId();  // Session ID (may be null)
    $issuer = $logoutToken->issuer();        // Issuer URL
    $audience = $logoutToken->audience();    // Your client ID

    echo "Received valid logout token from: {$issuer}\n";

    // Terminate sessions based on available claims
    if ($subject !== null && $sessionId !== null) {
        // Terminate specific session for specific user
        echo "Terminating session '{$sessionId}' for user '{$subject}'\n";
        terminateUserSession($subject, $sessionId);
    } elseif ($subject !== null) {
        // Terminate all sessions for this user
        echo "Terminating all sessions for user '{$subject}'\n";
        terminateAllUserSessions($subject);
    } elseif ($sessionId !== null) {
        // Terminate session by ID only
        echo "Terminating session '{$sessionId}'\n";
        terminateSession($sessionId);
    }

    // Return 200 OK to acknowledge successful processing
    http_response_code(200);
    echo "Logout processed successfully\n";

} catch (InvalidLogoutTokenException $e) {
    // Token is malformed or doesn't meet validation requirements
    http_response_code(400);
    echo "Invalid logout token: " . $e->getMessage() . "\n";

} catch (UntrustedLogoutTokenException $e) {
    // Token signature is invalid or issuer is not trusted
    http_response_code(403);
    echo "Untrusted logout token: " . $e->getMessage() . "\n";

} catch (LogoutTokenExpiredException $e) {
    // Token has expired
    http_response_code(410);
    echo "Logout token expired: " . $e->getMessage() . "\n";
}

// Session termination helper functions (implement these based on your session storage)

function terminateUserSession(string $userId, string $sessionId): void
{
    // Implementation example:
    // - Look up session by userId and sessionId
    // - Delete session from your session store (Redis, database, etc.)
    // - Invalidate any refresh tokens associated with the session
    // - Clear any application-specific caches

    echo "  → Session terminated\n";
}

function terminateAllUserSessions(string $userId): void
{
    // Implementation example:
    // - Find all sessions for the user
    // - Delete all sessions from your session store
    // - Invalidate all refresh tokens for the user
    // - Clear any application-specific caches

    echo "  → All user sessions terminated\n";
}

function terminateSession(string $sessionId): void
{
    // Implementation example:
    // - Look up session by sessionId
    // - Delete session from your session store
    // - Invalidate any refresh tokens associated with the session

    echo "  → Session terminated\n";
}
