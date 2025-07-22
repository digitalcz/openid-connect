<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

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
        $header = base64_encode(json_encode([
            'typ' => 'JWT',
            'alg' => 'RS256',
            'kid' => 'test-key-id',
        ]));

        $defaultPayload = [
            'iss' => 'https://example.com',
            'sub' => '1234567890',
            'aud' => 'test-client-id',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'test-nonce',
        ];

        $payload = array_merge($defaultPayload, $payload);
        $payloadEncoded = base64_encode(json_encode($payload));

        $signature = base64_encode('fake-signature');

        return "{$header}.{$payloadEncoded}.{$signature}";
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
