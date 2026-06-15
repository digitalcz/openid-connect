<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;

/**
 * Transport-security guard for outbound OIDC URLs.
 */
final class SecureUrl
{
    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '::1'];

    /**
     * Require an HTTPS URL, allowing plain HTTP only for loopback hosts.
     *
     * @throws DiscoveryException
     */
    public static function requireSecure(string $url): void
    {
        $parts = parse_url($url);

        // URI schemes are case-insensitive (RFC 3986 §3.1).
        $scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : null;

        if ($scheme === 'https') {
            return;
        }

        // parse_url wraps IPv6 hosts in brackets, e.g. "[::1]".
        $host = isset($parts['host']) ? strtolower(trim($parts['host'], '[]')) : null;

        if ($scheme === 'http' && $host !== null && in_array($host, self::LOOPBACK_HOSTS, true)) {
            return;
        }

        throw new DiscoveryException(sprintf('Insecure URL "%s": HTTPS is required.', $url));
    }
}
