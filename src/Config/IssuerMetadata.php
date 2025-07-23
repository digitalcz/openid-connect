<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\Util\ParamsTrait;

/**
 * Provider metadata with endpoints
 */
final readonly class IssuerMetadata
{
    use ParamsTrait;

    /**
     * @param array<string, string|string[]|bool> $metadata
     */
    public function __construct(private array $metadata)
    {
    }

    public function issuer(): string
    {
        return $this->string('issuer');
    }

    public function authorizationEndpoint(): string
    {
        return $this->string('authorization_endpoint');
    }

    public function tokenEndpoint(): string
    {
        return $this->string('token_endpoint');
    }

    public function jwksUri(): string
    {
        return $this->string('jwks_uri');
    }

    /**
     * @return array<string>
     */
    public function responseTypesSupported(): array
    {
        return $this->strings('response_types_supported');
    }

    /**
     * @return array<string>
     */
    public function subjectTypesSupported(): array
    {
        return $this->strings('subject_types_supported');
    }

    /**
     * @return array<string>
     */
    public function idTokenSigningAlgValuesSupported(): array
    {
        return $this->strings('id_token_signing_alg_values_supported');
    }

    /**
     * @return array<string>
     */
    public function tokenEndpointAuthSigningAlgValuesSupported(): array
    {
        return $this->strings('token_endpoint_auth_signing_alg_values_supported');
    }

    public function userinfoEndpoint(): string
    {
        return $this->string('userinfo_endpoint');
    }

    public function endSessionEndpoint(): string
    {
        return $this->string('end_session_endpoint');
    }

    public function introspectionEndpoint(): string
    {
        return $this->string('introspection_endpoint');
    }

    /**
     * @return array<string>
     */
    public function scopesSupported(): array
    {
        return $this->strings('scopes_supported');
    }

    /**
     * @return array<string>
     */
    public function claimsSupported(): array
    {
        return $this->strings('claims_supported');
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->metadata;
    }
}
