<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use InvalidArgumentException;

/**
 * PKCE (Proof Key for Code Exchange) utility for OAuth2 security enhancement.
 *
 * @see RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients
 */
final class Pkce
{
    /**
     * Generate a cryptographically random code verifier.
     *
     * @param int $length Length of the code verifier (43-128 characters)
     * @return string Base64URL-encoded code verifier
     */
    public static function generateCodeVerifier(int $length = 128): string
    {
        if ($length < 43 || $length > 128) {
            throw new InvalidArgumentException('Code verifier length must be between 43 and 128 characters');
        }

        // Generate random bytes and encode as base64url
        $bytes = random_bytes(max(32, (int) ceil($length * 3 / 4)));
        $verifier = Base64Url::encode($bytes);

        // Trim to exact length if needed
        return substr($verifier, 0, $length);
    }

    /**
     * Generate code challenge from code verifier.
     *
     * @param string $codeVerifier The code verifier
     * @param PkceMethod $method Challenge method
     * @return string The code challenge
     */
    public static function generateCodeChallenge(string $codeVerifier, PkceMethod $method = PkceMethod::S256): string
    {
        return match ($method) {
            PkceMethod::Plain => $codeVerifier,
            PkceMethod::S256 => Base64Url::encode(hash('sha256', $codeVerifier, true)),
        };
    }

    /**
     * Generate both code verifier and code challenge.
     *
     * @param PkceMethod $method Challenge method
     * @param int $verifierLength Length of the code verifier
     * @return array{verifier: string, challenge: string, method: string}
     */
    public static function generatePair(PkceMethod $method = PkceMethod::S256, int $verifierLength = 128): array
    {
        $verifier = self::generateCodeVerifier($verifierLength);
        $challenge = self::generateCodeChallenge($verifier, $method);

        return [
            'verifier' => $verifier,
            'challenge' => $challenge,
            'method' => $method->value,
        ];
    }
}
