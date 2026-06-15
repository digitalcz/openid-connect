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
        $scheme = parse_url($url, PHP_URL_SCHEME);

        if ($scheme === 'https') {
            return;
        }

        $host = parse_url($url, PHP_URL_HOST);

        // parse_url wraps IPv6 hosts in brackets, e.g. "[::1]".
        if (is_string($host)) {
            $host = strtolower(trim($host, '[]'));
        }

        if ($scheme === 'http' && is_string($host) && in_array($host, self::LOOPBACK_HOSTS, true)) {
            return;
        }

        throw new DiscoveryException(sprintf('Insecure URL "%s": HTTPS is required.', $url));
    }
}
