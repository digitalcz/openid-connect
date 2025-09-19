<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DigitalCz\OpenIDConnect\TestCase;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(JwtClientAssertionGenerator::class)]
class JwtClientAssertionGeneratorTest extends TestCase
{
    private const CLIENT_ID = 'test-client-id';
    private const AUDIENCE = 'https://example.com/token';
    private const CLIENT_SECRET = 'test-client-secret-that-is-long-enough-for-hmac-algorithms-minimum-256-bits';

    private JwtClientAssertionGenerator $generator;

    public function testGenerateWithSecret(): void
    {
        $jwt = $this->generator->generateWithSecret(self::CLIENT_ID, self::AUDIENCE, self::CLIENT_SECRET);

        $this->assertIsString($jwt);
        $this->assertStringContainsString('.', $jwt);

        // Parse JWT to verify structure
        $parsed = JWT::parse($jwt);
        $this->assertArrayHasKey('header', $parsed);
        $this->assertArrayHasKey('payload', $parsed);
        $this->assertArrayHasKey('signature', $parsed);

        // Verify header
        $header = $parsed['header'];
        $this->assertSame('HS256', $header['alg']);
        $this->assertSame('JWT', $header['typ']);

        // Verify payload
        $payload = $parsed['payload'];
        $this->assertSame(self::CLIENT_ID, $payload['iss']);
        $this->assertSame(self::CLIENT_ID, $payload['sub']);
        $this->assertSame(self::AUDIENCE, $payload['aud']);
        $this->assertArrayHasKey('jti', $payload);
        $this->assertArrayHasKey('iat', $payload);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertIsString($payload['jti']);
        $this->assertIsInt($payload['iat']);
        $this->assertIsInt($payload['exp']);
        $this->assertGreaterThan($payload['iat'], $payload['exp']);
    }

    public function testGenerateWithPrivateKey(): void
    {
        $privateKey = $this->generateRsaPrivateKey();

        $jwt = $this->generator->generateWithPrivateKey(self::CLIENT_ID, self::AUDIENCE, $privateKey);

        $this->assertIsString($jwt);

        // Parse JWT to verify structure
        $parsed = JWT::parse($jwt);
        $header = $parsed['header'];
        $payload = $parsed['payload'];

        // Verify header
        $this->assertSame('RS256', $header['alg']);
        $this->assertSame('JWT', $header['typ']);

        // Verify payload
        $this->assertSame(self::CLIENT_ID, $payload['iss']);
        $this->assertSame(self::CLIENT_ID, $payload['sub']);
        $this->assertSame(self::AUDIENCE, $payload['aud']);
        $this->assertArrayHasKey('jti', $payload);
        $this->assertArrayHasKey('iat', $payload);
        $this->assertArrayHasKey('exp', $payload);
    }

    public function testGenerateWithJwk(): void
    {
        $privateKey = $this->generateRsaPrivateKey();
        $jwk = JWKFactory::createFromKey($privateKey);

        $jwt = $this->generator->generateWithJwk(self::CLIENT_ID, self::AUDIENCE, $jwk);

        $this->assertIsString($jwt);

        // Parse JWT to verify structure
        $parsed = JWT::parse($jwt);
        $this->assertArrayHasKey('header', $parsed);
        $this->assertArrayHasKey('payload', $parsed);
    }

    /**
     * @param array<string, mixed> $params
     */
    #[DataProvider('algorithmProvider')]
    public function testDifferentAlgorithms(string $algorithm, string $keyType): void
    {
        if ($keyType === 'secret') {
            $jwt = $this->generator->generateWithSecret(
                self::CLIENT_ID,
                self::AUDIENCE,
                self::CLIENT_SECRET,
                $algorithm,
            );
        } else {
            $privateKey = $this->generateRsaPrivateKey();
            $jwt = $this->generator->generateWithPrivateKey(self::CLIENT_ID, self::AUDIENCE, $privateKey, $algorithm);
        }

        $parsed = JWT::parse($jwt);
        $header = $parsed['header'];

        $this->assertSame($algorithm, $header['alg']);
    }

    /**
     * @return array<string, array<string, string>>
     */
    public static function algorithmProvider(): array
    {
        return [
            'HS256' => ['algorithm' => 'HS256', 'keyType' => 'secret'],
            'HS384' => ['algorithm' => 'HS384', 'keyType' => 'secret'],
            'HS512' => ['algorithm' => 'HS512', 'keyType' => 'secret'],
            'RS256' => ['algorithm' => 'RS256', 'keyType' => 'private'],
            'RS384' => ['algorithm' => 'RS384', 'keyType' => 'private'],
            'RS512' => ['algorithm' => 'RS512', 'keyType' => 'private'],
        ];
    }

    public function testCustomExpirationTime(): void
    {
        $expirationSeconds = 600; // 10 minutes

        $jwt = $this->generator->generateWithSecret(
            self::CLIENT_ID,
            self::AUDIENCE,
            self::CLIENT_SECRET,
            'HS256',
            $expirationSeconds,
        );

        $parsed = JWT::parse($jwt);
        $payload = $parsed['payload'];

        // Verify the expiration time is approximately 10 minutes from issued time
        $expectedExp = $payload['iat'] + $expirationSeconds;
        $this->assertSame($expectedExp, $payload['exp']);
    }

    public function testUniqueJti(): void
    {
        $jwt1 = $this->generator->generateWithSecret(self::CLIENT_ID, self::AUDIENCE, self::CLIENT_SECRET);

        $jwt2 = $this->generator->generateWithSecret(self::CLIENT_ID, self::AUDIENCE, self::CLIENT_SECRET);

        $parsed1 = JWT::parse($jwt1);
        $parsed2 = JWT::parse($jwt2);

        $this->assertNotSame($parsed1['payload']['jti'], $parsed2['payload']['jti']);
    }

    public function testJwkWithKeyId(): void
    {
        $privateKey = $this->generateRsaPrivateKey();
        $jwk = JWKFactory::createFromKey($privateKey, null, ['kid' => 'test-key-id']);

        $jwt = $this->generator->generateWithJwk(self::CLIENT_ID, self::AUDIENCE, $jwk);

        $parsed = JWT::parse($jwt);
        $header = $parsed['header'];

        $this->assertSame('test-key-id', $header['kid']);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->generator = new JwtClientAssertionGenerator(new SimpleClock());
    }

    private function generateRsaPrivateKey(): string
    {
        $keyResource = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($keyResource, $privateKey);
        openssl_pkey_free($keyResource);

        return $privateKey;
    }
}
