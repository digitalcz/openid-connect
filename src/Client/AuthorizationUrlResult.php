<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

/**
 * Result of authorization URL creation containing the URL and security parameters.
 *
 * Security parameters are automatically generated if not provided:
 * - state: Always generated for CSRF protection
 * - nonce: Generated only when 'openid' scope is present (for ID token validation)
 * - codeVerifier: Generated when PKCE is enabled in client configuration
 */
final readonly class AuthorizationUrlResult
{
    public function __construct(
        private string $url,
        private string $state,
        private ?string $nonce = null,
        private ?string $codeVerifier = null,
    ) {
    }

    public function url(): string
    {
        return $this->url;
    }

    public function state(): string
    {
        return $this->state;
    }

    public function nonce(): ?string
    {
        return $this->nonce;
    }

    public function codeVerifier(): ?string
    {
        return $this->codeVerifier;
    }

    public function __toString(): string
    {
        return $this->url;
    }
}
