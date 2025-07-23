<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use ArrayObject;
use DigitalCz\OpenIDConnect\TestCase;
use Generator;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;

#[CoversClass(ResourceServer::class)]
class ResourceServerTest extends TestCase
{
    private AccessTokenValidator&MockObject $jwtValidator;
    private AccessTokenValidator&MockObject $opaqueValidator;
    private JwtAccessToken $jwtToken;
    private OpaqueAccessToken $opaqueToken;
    private ValidatedAccessToken $validatedToken;

    public function testConstructorWithSingleValidator(): void
    {
        $resourceServer = new ResourceServer([$this->jwtValidator]);

        $this->assertInstanceOf(ResourceServer::class, $resourceServer);
    }

    public function testConstructorWithMultipleValidators(): void
    {
        $resourceServer = new ResourceServer([$this->jwtValidator, $this->opaqueValidator]);

        $this->assertInstanceOf(ResourceServer::class, $resourceServer);
    }

    public function testConstructorWithEmptyValidators(): void
    {
        $resourceServer = new ResourceServer([]);

        $this->assertInstanceOf(ResourceServer::class, $resourceServer);
    }

    public function testIntrospectWithJwtToken(): void
    {
        $this->jwtValidator->expects($this->once())
            ->method('supports')
            ->with($this->jwtToken)
            ->willReturn(true);

        $this->jwtValidator->expects($this->once())
            ->method('validate')
            ->with($this->jwtToken)
            ->willReturn($this->validatedToken);

        $this->opaqueValidator->expects($this->never())
            ->method('supports');

        $resourceServer = new ResourceServer([$this->jwtValidator, $this->opaqueValidator]);

        $result = $resourceServer->introspect($this->jwtToken);

        $this->assertSame($this->validatedToken, $result);
    }

    public function testIntrospectWithOpaqueToken(): void
    {
        $this->jwtValidator->expects($this->once())
            ->method('supports')
            ->with($this->opaqueToken)
            ->willReturn(false);

        $this->opaqueValidator->expects($this->once())
            ->method('supports')
            ->with($this->opaqueToken)
            ->willReturn(true);

        $this->opaqueValidator->expects($this->once())
            ->method('validate')
            ->with($this->opaqueToken)
            ->willReturn($this->validatedToken);

        $resourceServer = new ResourceServer([$this->jwtValidator, $this->opaqueValidator]);

        $result = $resourceServer->introspect($this->opaqueToken);

        $this->assertSame($this->validatedToken, $result);
    }

    public function testIntrospectWithUnsupportedToken(): void
    {
        $this->jwtValidator->expects($this->once())
            ->method('supports')
            ->with($this->jwtToken)
            ->willReturn(false);

        $this->opaqueValidator->expects($this->once())
            ->method('supports')
            ->with($this->jwtToken)
            ->willReturn(false);

        $resourceServer = new ResourceServer([$this->jwtValidator, $this->opaqueValidator]);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'No AccessTokenValidator supporting DigitalCz\OpenIDConnect\ResourceServer\JwtAccessToken.',
        );

        $resourceServer->introspect($this->jwtToken);
    }

    public function testIntrospectWithNoValidators(): void
    {
        $resourceServer = new ResourceServer([]);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'No AccessTokenValidator supporting DigitalCz\OpenIDConnect\ResourceServer\JwtAccessToken.',
        );

        $resourceServer->introspect($this->jwtToken);
    }

    public function testIntrospectUsesFirstMatchingValidator(): void
    {
        $firstValidator = $this->createMock(AccessTokenValidator::class);
        $secondValidator = $this->createMock(AccessTokenValidator::class);

        $firstValidator->expects($this->once())
            ->method('supports')
            ->with($this->jwtToken)
            ->willReturn(true);

        $firstValidator->expects($this->once())
            ->method('validate')
            ->with($this->jwtToken)
            ->willReturn($this->validatedToken);

        // Second validator should not be called since first one supports the token
        $secondValidator->expects($this->never())
            ->method('supports');

        $resourceServer = new ResourceServer([$firstValidator, $secondValidator]);

        $result = $resourceServer->introspect($this->jwtToken);

        $this->assertSame($this->validatedToken, $result);
    }

    public function testIntrospectSkipsUnsupportingValidators(): void
    {
        $unsupportingValidator = $this->createMock(AccessTokenValidator::class);
        $supportingValidator = $this->createMock(AccessTokenValidator::class);

        $unsupportingValidator->expects($this->once())
            ->method('supports')
            ->with($this->jwtToken)
            ->willReturn(false);

        $unsupportingValidator->expects($this->never())
            ->method('validate');

        $supportingValidator->expects($this->once())
            ->method('supports')
            ->with($this->jwtToken)
            ->willReturn(true);

        $supportingValidator->expects($this->once())
            ->method('validate')
            ->with($this->jwtToken)
            ->willReturn($this->validatedToken);

        $resourceServer = new ResourceServer([$unsupportingValidator, $supportingValidator]);

        $result = $resourceServer->introspect($this->jwtToken);

        $this->assertSame($this->validatedToken, $result);
    }

    public function testIntrospectWithIterableValidators(): void
    {
        // Test with different iterable types
        $validators = new ArrayObject([$this->jwtValidator]);

        $this->jwtValidator->expects($this->once())
            ->method('supports')
            ->with($this->jwtToken)
            ->willReturn(true);

        $this->jwtValidator->expects($this->once())
            ->method('validate')
            ->with($this->jwtToken)
            ->willReturn($this->validatedToken);

        $resourceServer = new ResourceServer($validators);

        $result = $resourceServer->introspect($this->jwtToken);

        $this->assertSame($this->validatedToken, $result);
    }

    public function testIntrospectWithGeneratorValidators(): void
    {
        $generatorFunction = function (): Generator {
            yield $this->jwtValidator;
        };

        $this->jwtValidator->expects($this->once())
            ->method('supports')
            ->with($this->jwtToken)
            ->willReturn(true);

        $this->jwtValidator->expects($this->once())
            ->method('validate')
            ->with($this->jwtToken)
            ->willReturn($this->validatedToken);

        $resourceServer = new ResourceServer($generatorFunction());

        $result = $resourceServer->introspect($this->jwtToken);

        $this->assertSame($this->validatedToken, $result);
    }

    public function testValidatorOrderMatters(): void
    {
        $validator1 = $this->createMock(AccessTokenValidator::class);
        $validator2 = $this->createMock(AccessTokenValidator::class);

        // Both validators support the token, but first one should be used
        $validator1->expects($this->once())
            ->method('supports')
            ->with($this->jwtToken)
            ->willReturn(true);

        $validator1->expects($this->once())
            ->method('validate')
            ->with($this->jwtToken)
            ->willReturn($this->validatedToken);

        // Second validator should not be checked since first one already supports
        $validator2->expects($this->never())
            ->method('supports');

        $resourceServer = new ResourceServer([$validator1, $validator2]);

        $result = $resourceServer->introspect($this->jwtToken);

        $this->assertSame($this->validatedToken, $result);
    }

    public function testReadonlyClassBehavior(): void
    {
        $resourceServer = new ResourceServer([$this->jwtValidator]);

        // Verify the class maintains its state consistently
        $this->assertInstanceOf(ResourceServer::class, $resourceServer);

        // The readonly class should be immutable
        $resourceServer2 = new ResourceServer([$this->jwtValidator]);
        $this->assertNotSame($resourceServer, $resourceServer2);
    }

    public function testExceptionMessageContainsTokenClassName(): void
    {
        $customToken = new class ('test-token') extends AccessToken {
        };

        $resourceServer = new ResourceServer([]);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/No AccessTokenValidator supporting .*@anonymous/');

        $resourceServer->introspect($customToken);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->jwtValidator = $this->createMock(AccessTokenValidator::class);
        $this->opaqueValidator = $this->createMock(AccessTokenValidator::class);

        $this->jwtToken = new JwtAccessToken($this->createSampleJwt());
        $this->opaqueToken = new OpaqueAccessToken('opaque-token-123');

        $this->validatedToken = new ValidatedAccessToken(
            $this->jwtToken,
            [
                'sub' => 'user123',
                'iss' => 'https://auth.example.com',
                'aud' => 'test-client-id',
                'exp' => time() + 3600,
                'scope' => 'openid profile',
            ],
        );
    }
}
