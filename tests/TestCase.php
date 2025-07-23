<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Util\Base64Url;
use DigitalCz\OpenIDConnect\Util\Json;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

abstract class TestCase extends BaseTestCase
{
    /**
     * Create a mock HTTP client with predefined responses
     *
     * @param MockResponse[] $responses
     */
    protected function createMockHttpClient(array $responses): MockHttpClient
    {
        return new MockHttpClient($responses);
    }

    /**
     * Create a mock HTTP response
     *
     * @param array<string, string> $headers
     */
    protected function createMockResponse(
        string $body = '',
        int $status = 200,
        array $headers = ['content-type' => 'application/json'],
    ): MockResponse {
        return new MockResponse($body, [
            'http_code' => $status,
            'response_headers' => $headers,
        ]);
    }

    /**
     * Create a sample JWT token for testing
     *
     * @param array<string, mixed> $payload
     */
    protected function createSampleJwt(array $payload = []): string
    {
        $header = [
            'typ' => 'JWT',
            'alg' => 'RS256',
            'kid' => 'test-key-id',
        ];

        $defaultPayload = [
            'iss' => 'https://example.com',
            'sub' => '1234567890',
            'aud' => 'test-client-id',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'test-nonce',
        ];

        $payload = array_merge($defaultPayload, $payload);

        return $this->createCustomJwt($header, $payload);
    }

    /**
     * Create a JWT with custom header and payload
     *
     * @param array<string, mixed> $header
     * @param array<string, mixed> $payload
     */
    protected function createCustomJwt(array $header, array $payload): string
    {
        $headerEncoded = Base64Url::encode(Json::encode($header));
        $payloadEncoded = Base64Url::encode(Json::encode($payload));
        $signature = Base64Url::encode('fake-signature-for-testing');

        return "{$headerEncoded}.{$payloadEncoded}.{$signature}";
    }

    /**
     * Create an invalid JWT for testing error scenarios
     */
    protected function createInvalidJwt(): string
    {
        return 'invalid.jwt.token';
    }

    /**
     * Create an expired JWT token for testing
     *
     * @param array<string, mixed> $payload
     */
    protected function createExpiredJwt(array $payload = []): string
    {
        $expiredPayload = array_merge($payload, [
            'exp' => time() - 3600, // Expired 1 hour ago
            'iat' => time() - 7200, // Issued 2 hours ago
        ]);

        return $this->createSampleJwt($expiredPayload);
    }

    /**
     * Create a JWT with missing required claims for testing validation
     *
     * @param string[] $missingClaims
     */
    protected function createJwtWithMissingClaims(array $missingClaims): string
    {
        $payload = [
            'iss' => 'https://example.com',
            'sub' => '1234567890',
            'aud' => 'test-client-id',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'test-nonce',
        ];

        // Remove specified claims
        foreach ($missingClaims as $claim) {
            unset($payload[$claim]);
        }

        return $this->createSampleJwt($payload);
    }

    /**
     * Create sample JWKS response
     *
     * @return array<string, mixed>
     */
    protected function createSampleJwks(): array
    {
        return [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'kid' => 'test-key-id',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'n' => 'sample-modulus',
                    'e' => 'AQAB',
                ],
            ],
        ];
    }

    /**
     * Create sample OpenID Connect discovery document
     *
     * @return array<string, mixed>
     */
    protected function createSampleDiscoveryDocument(): array
    {
        return [
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/authorize',
            'token_endpoint' => 'https://example.com/token',
            'userinfo_endpoint' => 'https://example.com/userinfo',
            'jwks_uri' => 'https://example.com/.well-known/jwks.json',
            'response_types_supported' => ['code', 'id_token', 'code id_token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => ['openid', 'profile', 'email'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic'],
            'claims_supported' => ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'name', 'email'],
        ];
    }

    /**
     * Create sample OAuth2 token response
     *
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    protected function createSampleTokenResponse(array $overrides = []): array
    {
        $defaults = [
            'access_token' => 'sample-access-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'sample-refresh-token',
            'id_token' => $this->createSampleJwt(),
            'scope' => 'openid profile email',
        ];

        return array_merge($defaults, $overrides);
    }
}
