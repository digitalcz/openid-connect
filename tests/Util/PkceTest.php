<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DigitalCz\OpenIDConnect\TestCase;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Pkce::class)]
class PkceTest extends TestCase
{
    public function testGenerateCodeVerifier(): void
    {
        $verifier = Pkce::generateCodeVerifier();

        $this->assertIsString($verifier);
        $this->assertSame(128, strlen($verifier));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $verifier);
    }

    public function testGenerateCodeVerifierWithCustomLength(): void
    {
        $verifier = Pkce::generateCodeVerifier(64);

        $this->assertSame(64, strlen($verifier));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $verifier);
    }

    public function testGenerateCodeVerifierWithInvalidLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Code verifier length must be between 43 and 128 characters');

        Pkce::generateCodeVerifier(42);
    }

    public function testGenerateCodeVerifierWithTooLongLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Code verifier length must be between 43 and 128 characters');

        Pkce::generateCodeVerifier(129);
    }

    public function testGenerateCodeVerifierIsRandom(): void
    {
        $verifier1 = Pkce::generateCodeVerifier();
        $verifier2 = Pkce::generateCodeVerifier();

        $this->assertNotSame($verifier1, $verifier2);
    }

    public function testGenerateCodeChallengeWithS256(): void
    {
        $verifier = 'test-code-verifier-123';
        $challenge = Pkce::generateCodeChallenge($verifier, PkceMethod::S256);

        $expectedChallenge = Base64Url::encode(hash('sha256', $verifier, true));
        $this->assertSame($expectedChallenge, $challenge);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $challenge);
    }

    public function testGenerateCodeChallengeWithPlain(): void
    {
        $verifier = 'test-code-verifier-123';
        $challenge = Pkce::generateCodeChallenge($verifier, PkceMethod::Plain);

        $this->assertSame($verifier, $challenge);
    }

    public function testGenerateCodeChallengeDefaultsToS256(): void
    {
        $verifier = 'test-code-verifier-123';
        $challenge = Pkce::generateCodeChallenge($verifier);

        $expectedChallenge = Base64Url::encode(hash('sha256', $verifier, true));
        $this->assertSame($expectedChallenge, $challenge);
    }

    public function testGeneratePairWithS256(): void
    {
        $pair = Pkce::generatePair(PkceMethod::S256);

        $this->assertIsArray($pair);
        $this->assertArrayHasKey('verifier', $pair);
        $this->assertArrayHasKey('challenge', $pair);
        $this->assertArrayHasKey('method', $pair);

        $this->assertIsString($pair['verifier']);
        $this->assertIsString($pair['challenge']);
        $this->assertSame(PkceMethod::S256->value, $pair['method']);

        $this->assertSame(128, strlen($pair['verifier']));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $pair['verifier']);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $pair['challenge']);

        // Verify challenge was generated correctly
        $expectedChallenge = Base64Url::encode(hash('sha256', $pair['verifier'], true));
        $this->assertSame($expectedChallenge, $pair['challenge']);
    }

    public function testGeneratePairWithPlain(): void
    {
        $pair = Pkce::generatePair(PkceMethod::Plain);

        $this->assertSame(PkceMethod::Plain->value, $pair['method']);
        $this->assertSame($pair['verifier'], $pair['challenge']);
    }

    public function testGeneratePairWithCustomVerifierLength(): void
    {
        $pair = Pkce::generatePair(PkceMethod::S256, 64);

        $this->assertSame(64, strlen($pair['verifier']));
    }

    public function testGeneratePairDefaultsToS256(): void
    {
        $pair = Pkce::generatePair();

        $this->assertSame(PkceMethod::S256->value, $pair['method']);
        $this->assertSame(128, strlen($pair['verifier']));
    }

    public function testEnumValues(): void
    {
        $this->assertSame('S256', PkceMethod::S256->value);
        $this->assertSame('plain', PkceMethod::Plain->value);
    }
}
