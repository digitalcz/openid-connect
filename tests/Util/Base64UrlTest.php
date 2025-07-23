<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DigitalCz\OpenIDConnect\TestCase;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(Base64Url::class)]
class Base64UrlTest extends TestCase
{
    #[DataProvider('encodeDecodeProvider')]
    public function testEncodeDecode(string $input, string $expectedEncoded): void
    {
        // Test encoding
        $encoded = Base64Url::encode($input);
        $this->assertSame($expectedEncoded, $encoded);

        // Test decoding
        $decoded = Base64Url::decode($encoded);
        $this->assertSame($input, $decoded);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function encodeDecodeProvider(): array
    {
        return [
            'empty string' => ['', ''],
            'simple text' => ['hello', 'aGVsbG8'],
            'text with special chars' => ['hello world!', 'aGVsbG8gd29ybGQh'],
            'JSON object' => ['{"sub":"1234567890","name":"John Doe"}', 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0'],
            'binary data' => ["\x00\x01\x02\x03", 'AAECAw'],
            'padding test 1' => ['f', 'Zg'],
            'padding test 2' => ['fo', 'Zm8'],
            'padding test 3' => ['foo', 'Zm9v'],
            'unicode characters' => ['Hello 🌍', 'SGVsbG8g8J-MjQ'],
        ];
    }

    public function testDecodeInvalidInput(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid base64url string');

        Base64Url::decode('invalid@#$');
    }

    public function testEncodeDecodeRoundTrip(): void
    {
        $originalData = json_encode([
            'iss' => 'https://example.com',
            'sub' => '1234567890',
            'aud' => 'client-id',
            'exp' => 1609459200,
            'iat' => 1609372800,
            'nonce' => 'random-nonce-value',
        ]);

        $encoded = Base64Url::encode($originalData);
        $decoded = Base64Url::decode($encoded);

        $this->assertSame($originalData, $decoded);
    }

    public function testCompatibilityWithStandardBase64(): void
    {
        $data = 'This is a test string that will produce base64 with padding';

        // Test that Base64Url encoding doesn't have padding or unsafe characters
        $base64UrlEncoded = Base64Url::encode($data);

        $this->assertStringNotContainsString('=', $base64UrlEncoded, 'Base64URL should not contain padding');
        $this->assertStringNotContainsString('+', $base64UrlEncoded, 'Base64URL should not contain +');
        $this->assertStringNotContainsString('/', $base64UrlEncoded, 'Base64URL should not contain /');

        // But should decode to the same result
        $this->assertSame($data, Base64Url::decode($base64UrlEncoded));
    }

    public function testLargeData(): void
    {
        // Test with larger data
        $largeData = str_repeat('Lorem ipsum dolor sit amet, ', 100);

        $encoded = Base64Url::encode($largeData);
        $decoded = Base64Url::decode($encoded);

        $this->assertSame($largeData, $decoded);
        $this->assertStringNotContainsString('=', $encoded);
        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
    }
}
