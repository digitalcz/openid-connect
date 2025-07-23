<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use stdClass;
use UnexpectedValueException;

#[CoversTrait(ParamsTrait::class)]
class ParamsTraitTest extends TestCase
{
    private TestParamsClass $testClass;

    public function testHasWithExistingKey(): void
    {
        $this->testClass = new TestParamsClass(['key1' => 'value1', 'key2' => 'value2']);

        $this->assertTrue($this->testClass->has('key1'));
        $this->assertTrue($this->testClass->has('key2'));
    }

    public function testHasWithNonExistingKey(): void
    {
        $this->testClass = new TestParamsClass(['key1' => 'value1']);

        $this->assertFalse($this->testClass->has('nonexistent'));
    }

    public function testHasWithNullValue(): void
    {
        $this->testClass = new TestParamsClass(['key1' => null]);

        $this->assertTrue($this->testClass->has('key1'));
    }

    public function testGetWithExistingKey(): void
    {
        $this->testClass = new TestParamsClass(['key1' => 'value1', 'key2' => 42]);

        $this->assertSame('value1', $this->testClass->get('key1'));
        $this->assertSame(42, $this->testClass->get('key2'));
    }

    public function testGetWithNonExistingKeyReturnsDefault(): void
    {
        $this->testClass = new TestParamsClass(['key1' => 'value1']);

        $this->assertNull($this->testClass->get('nonexistent'));
        $this->assertSame('default', $this->testClass->get('nonexistent', 'default'));
        $this->assertSame(123, $this->testClass->get('nonexistent', 123));
    }

    public function testGetWithNullValue(): void
    {
        $this->testClass = new TestParamsClass(['key1' => null]);

        $this->assertNull($this->testClass->get('key1'));
        $this->assertNull($this->testClass->get('key1', 'default'));
    }

    public function testIntegerWithValidInteger(): void
    {
        $this->testClass = new TestParamsClass(['age' => 25, 'count' => 0, 'negative' => -10]);

        $this->assertSame(25, $this->testClass->integer('age'));
        $this->assertSame(0, $this->testClass->integer('count'));
        $this->assertSame(-10, $this->testClass->integer('negative'));
    }

    public function testIntegerWithNullValue(): void
    {
        $this->testClass = new TestParamsClass(['age' => null]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter "age" is required and must be an integer.');
        $this->testClass->integer('age');
    }

    public function testIntegerWithMissingKey(): void
    {
        $this->testClass = new TestParamsClass([]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter "age" is required and must be an integer.');
        $this->testClass->integer('age');
    }

    /**
     * @param mixed $value
     */
    #[DataProvider('invalidIntegerProvider')]
    public function testIntegerWithInvalidType($value): void
    {
        $this->testClass = new TestParamsClass(['value' => $value]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter value "value" cannot be converted to "integer".');
        $this->testClass->integer('value');
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function invalidIntegerProvider(): array
    {
        return [
            'string' => ['not_integer'],
            'float' => [3.14],
            'boolean true' => [true],
            'boolean false' => [false],
            'array' => [[]],
            'object' => [new stdClass()],
        ];
    }

    public function testBooleanWithValidBoolean(): void
    {
        $this->testClass = new TestParamsClass(['flag1' => true, 'flag2' => false]);

        $this->assertTrue($this->testClass->boolean('flag1'));
        $this->assertFalse($this->testClass->boolean('flag2'));
    }

    public function testBooleanWithNullValue(): void
    {
        $this->testClass = new TestParamsClass(['flag' => null]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter "flag" is required and must be a boolean.');
        $this->testClass->boolean('flag');
    }

    public function testBooleanWithMissingKey(): void
    {
        $this->testClass = new TestParamsClass([]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter "flag" is required and must be a boolean.');
        $this->testClass->boolean('flag');
    }

    /**
     * @param mixed $value
     */
    #[DataProvider('invalidBooleanProvider')]
    public function testBooleanWithInvalidType($value): void
    {
        $this->testClass = new TestParamsClass(['value' => $value]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter value "value" cannot be converted to "boolean".');
        $this->testClass->boolean('value');
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function invalidBooleanProvider(): array
    {
        return [
            'string' => ['not_boolean'],
            'integer' => [1],
            'float' => [3.14],
            'array' => [[]],
            'object' => [new stdClass()],
        ];
    }

    public function testStringWithValidString(): void
    {
        $this->testClass = new TestParamsClass(['name' => 'John', 'empty' => '', 'number_string' => '123']);

        $this->assertSame('John', $this->testClass->string('name'));
        $this->assertSame('', $this->testClass->string('empty'));
        $this->assertSame('123', $this->testClass->string('number_string'));
    }

    public function testStringWithStringableObject(): void
    {
        $stringable = new class {
            public function __toString(): string
            {
                return 'stringable_value';
            }
        };

        $this->testClass = new TestParamsClass(['stringable' => $stringable]);

        $this->assertSame('stringable_value', $this->testClass->string('stringable'));
    }

    public function testStringWithNullValue(): void
    {
        $this->testClass = new TestParamsClass(['name' => null]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter "name" is required and must be a string.');
        $this->testClass->string('name');
    }

    public function testStringWithMissingKey(): void
    {
        $this->testClass = new TestParamsClass([]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter "name" is required and must be a string.');
        $this->testClass->string('name');
    }

    /**
     * @param mixed $value
     */
    #[DataProvider('invalidStringProvider')]
    public function testStringWithInvalidType($value): void
    {
        $this->testClass = new TestParamsClass(['value' => $value]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter value "value" cannot be converted to "string".');
        $this->testClass->string('value');
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function invalidStringProvider(): array
    {
        return [
            'integer' => [123],
            'float' => [3.14],
            'boolean true' => [true],
            'boolean false' => [false],
            'array' => [[]],
            'object' => [new stdClass()],
        ];
    }

    public function testStringsWithValidStringArray(): void
    {
        $this->testClass = new TestParamsClass([
            'tags' => ['tag1', 'tag2', 'tag3'],
            'empty_array' => [],
            'mixed_scalars' => ['string', 123, 3.14, true, false],
        ]);

        $this->assertSame(['tag1', 'tag2', 'tag3'], $this->testClass->strings('tags'));
        $this->assertSame([], $this->testClass->strings('empty_array'));
        $this->assertSame(['string', '123', '3.14', '1', ''], $this->testClass->strings('mixed_scalars'));
    }

    public function testStringsWithStringableObjects(): void
    {
        $stringable = new class {
            public function __toString(): string
            {
                return 'stringable_item';
            }
        };

        $this->testClass = new TestParamsClass(['items' => ['regular_string', $stringable]]);

        $this->assertSame(['regular_string', 'stringable_item'], $this->testClass->strings('items'));
    }

    public function testStringsWithNullValue(): void
    {
        $this->testClass = new TestParamsClass(['tags' => null]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter "tags" is required and must be an array of strings.');
        $this->testClass->strings('tags');
    }

    public function testStringsWithMissingKey(): void
    {
        $this->testClass = new TestParamsClass([]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter "tags" is required and must be an array of strings.');
        $this->testClass->strings('tags');
    }

    public function testStringsWithNonArrayValue(): void
    {
        $this->testClass = new TestParamsClass(['tags' => 'not_array']);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter value "tags" cannot be converted to "array".');
        $this->testClass->strings('tags');
    }

    public function testStringsWithNonConvertibleArrayItem(): void
    {
        $this->testClass = new TestParamsClass(['tags' => ['valid_string', ['nested_array']]]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter value "tags" cannot be converted to "string".');
        $this->testClass->strings('tags');
    }

    public function testStringsWithObjectInArray(): void
    {
        $nonStringable = new stdClass();
        $this->testClass = new TestParamsClass(['tags' => ['valid_string', $nonStringable]]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter value "tags" cannot be converted to "string".');
        $this->testClass->strings('tags');
    }

    /**
     * @param mixed $value
     */
    #[DataProvider('invalidArrayProvider')]
    public function testStringsWithInvalidArrayType($value): void
    {
        $this->testClass = new TestParamsClass(['value' => $value]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parameter value "value" cannot be converted to "array".');
        $this->testClass->strings('value');
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function invalidArrayProvider(): array
    {
        return [
            'string' => ['not_array'],
            'integer' => [123],
            'float' => [3.14],
            'boolean true' => [true],
            'boolean false' => [false],
            'object' => [new stdClass()],
        ];
    }

    public function testComplexDataTypes(): void
    {
        $stringable = new class {
            public function __toString(): string
            {
                return 'complex_stringable';
            }
        };

        $this->testClass = new TestParamsClass([
            'integer_param' => 42,
            'boolean_param' => true,
            'string_param' => 'test_string',
            'stringable_param' => $stringable,
            'array_param' => ['item1', 'item2', 123, $stringable],
            'null_param' => null,
            'mixed_array' => ['string', 42, 3.14, true, false],
        ]);

        // Test all methods with complex data
        $this->assertTrue($this->testClass->has('integer_param'));
        $this->assertSame(42, $this->testClass->get('integer_param'));
        $this->assertSame(42, $this->testClass->integer('integer_param'));

        $this->assertTrue($this->testClass->boolean('boolean_param'));
        $this->assertSame('test_string', $this->testClass->string('string_param'));
        $this->assertSame('complex_stringable', $this->testClass->string('stringable_param'));

        $expectedArray = ['item1', 'item2', '123', 'complex_stringable'];
        $this->assertSame($expectedArray, $this->testClass->strings('array_param'));

        $expectedMixedArray = ['string', '42', '3.14', '1', ''];
        $this->assertSame($expectedMixedArray, $this->testClass->strings('mixed_array'));
    }
}

/**
 * Test class that uses ParamsTrait for testing purposes
 */
class TestParamsClass // @phpcs:ignore
{
    use ParamsTrait;

    /**
     * @param array<string, mixed> $data
     */
    public function __construct(private array $data)
    {
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->data;
    }
}
