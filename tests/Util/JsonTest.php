<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DigitalCz\OpenIDConnect\TestCase;
use JsonException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(Json::class)]
class JsonTest extends TestCase
{
    /**
     * @param array<string, mixed> $value
     */
    #[DataProvider('encodeProvider')]
    public function testEncode(array $value, string $expected): void
    {
        $result = Json::encode($value);
        $this->assertSame($expected, $result);
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function encodeProvider(): array
    {
        return [
            'empty array' => [[], '[]'],
            'indexed array' => [[1, 2, 3], '[1,2,3]'],
            'associative array' => [['key' => 'value'], '{"key":"value"}'],
            'nested object' => [['user' => ['id' => 1, 'name' => 'John']], '{"user":{"id":1,"name":"John"}}'],
            'mixed types' => [
                ['null' => null, 'bool' => true, 'int' => 123, 'float' => 12.34, 'string' => 'hello'],
                '{"null":null,"bool":true,"int":123,"float":12.34,"string":"hello"}',
            ],
        ];
    }

    /**
     * @param array<string, mixed> $expected
     */
    #[DataProvider('decodeProvider')]
    public function testDecode(string $json, array $expected): void
    {
        $result = Json::decode($json);
        $this->assertEquals($expected, $result);
    }

    /**
     * @return array<string, array{string, array<string, mixed>}>
     */
    public static function decodeProvider(): array
    {
        return [
            'empty array' => ['[]', []],
            'indexed array' => ['[1,2,3]', [1, 2, 3]],
            'associative array' => ['{"key":"value"}', ['key' => 'value']],
            'nested object' => ['{"user":{"id":1,"name":"John"}}', ['user' => ['id' => 1, 'name' => 'John']]],
            'mixed types' => [
                '{"null":null,"bool":true,"int":123,"float":12.34,"string":"hello"}',
                ['null' => null, 'bool' => true, 'int' => 123, 'float' => 12.34, 'string' => 'hello'],
            ],
        ];
    }

    public function testEncodeDecodeRoundTrip(): void
    {
        $originalData = [
            'iss' => 'https://example.com',
            'sub' => '1234567890',
            'aud' => ['client-id', 'another-client'],
            'exp' => 1609459200,
            'iat' => 1609372800,
            'scopes' => ['openid', 'profile', 'email'],
            'user' => [
                'name' => 'John Doe',
                'email' => 'john@example.com',
                'verified' => true,
                'metadata' => null,
            ],
        ];

        $encoded = Json::encode($originalData);
        $decoded = Json::decode($encoded);

        $this->assertEquals($originalData, $decoded);
    }

    public function testEncodeInvalidData(): void
    {
        // Create an array with a resource that cannot be encoded to JSON
        $resource = fopen('php://memory', 'r');

        $this->expectException(JsonException::class);
        Json::encode(['resource' => $resource]);

        fclose($resource);
    }

    public function testDecodeInvalidJson(): void
    {
        $this->expectException(JsonException::class);
        Json::decode('invalid json string');
    }

    public function testDecodeMalformedJson(): void
    {
        $this->expectException(JsonException::class);
        Json::decode('{"incomplete": }');
    }

    public function testEncodeUnicodeCharacters(): void
    {
        $data = ['message' => 'Hello 🌍 World! 你好'];
        $encoded = Json::encode($data);

        // JSON encode escapes Unicode by default, so test round trip instead
        $decoded = Json::decode($encoded);
        $this->assertSame($data, $decoded);

        // Verify the encoded string is valid JSON
        $this->assertIsString($encoded);
        $this->assertStringContainsString('message', $encoded);
    }

    public function testEncodeSpecialFloats(): void
    {
        $this->expectException(JsonException::class);
        Json::encode(['value' => NAN]);
    }

    public function testDecodeNonArrayJson(): void
    {
        // Test that decode throws exception when JSON is valid but not an array
        $this->expectException(JsonException::class);
        $this->expectExceptionMessage('Invalid JSON');
        Json::decode('"just a string"');
    }

    public function testDecodeEmptyString(): void
    {
        $this->expectException(JsonException::class);
        Json::decode('');
    }
}
