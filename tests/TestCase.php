<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Util\Base64Url;
use DigitalCz\OpenIDConnect\Util\Json;
use DigitalCz\OpenIDConnect\Util\SignatureAlgorithmsFactory;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    private ?JWK $signingKey = null;

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
     * The RSA key used to sign real JWTs in tests (cached per test instance).
     */
    protected function signingKey(): JWK
    {
        return $this->signingKey ??= JWKFactory::createRSAKey(
            2048,
            ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'test-key-id'],
        );
    }

    /**
     * Public JWKS matching {@see signingKey()}, suitable for a JwksLoader mock.
     *
     * Returns a plain array (as a decoded JWKS document would be), so it can be
     * passed to JWKSet::createFromKeyData() exactly like a real loader response.
     *
     * @return array<string, mixed>
     */
    protected function publicJwks(): array
    {
        return ['keys' => [$this->signingKey()->toPublic()->all()]];
    }

    /**
     * Create a real RS256-signed compact JWT verifiable against {@see publicJwks()}.
     *
     * A claim or header passed as null is omitted (e.g. ['aud' => null] or,
     * for the header, ['typ' => null]).
     *
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $header
     */
    protected function createSignedJwt(array $payload = [], array $header = []): string
    {
        $header = array_filter(
            array_merge([
                'typ' => 'JWT',
                'alg' => 'RS256',
                'kid' => 'test-key-id',
            ], $header),
            static fn (mixed $value): bool => $value !== null,
        );

        $defaultPayload = [
            'iss' => 'https://auth.example.com',
            'sub' => '1234567890',
            'aud' => 'test-audience',
            'exp' => time() + 3600,
            'iat' => time(),
        ];

        $payload = array_filter(
            array_merge($defaultPayload, $payload),
            static fn (mixed $value): bool => $value !== null,
        );

        $algorithmManager = (new AlgorithmManagerFactory(SignatureAlgorithmsFactory::create()))->create(['RS256']);

        $jws = (new JWSBuilder($algorithmManager))
            ->create()
            ->withPayload(Json::encode($payload))
            ->addSignature($this->signingKey(), $header)
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }
}
