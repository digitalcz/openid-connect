<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use RuntimeException;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

#[CoversClass(OpaqueAccessTokenValidator::class)]
class OpaqueAccessTokenValidatorTest extends TestCase
{
    private Config&MockObject $config;
    private HttpClientInterface&MockObject $httpClient;
    private IssuerMetadata $issuerMetadata;
    private ClientMetadata $clientMetadata;
    private OpaqueAccessTokenValidator $validator;

    public function testConstructor(): void
    {
        $validator = new OpaqueAccessTokenValidator($this->config, $this->httpClient);

        $this->assertInstanceOf(OpaqueAccessTokenValidator::class, $validator);
    }

    public function testSupportsOpaqueAccessToken(): void
    {
        $opaqueToken = new OpaqueAccessToken('opaque-token-123');

        $supports = $this->validator->supports($opaqueToken);

        $this->assertTrue($supports);
    }

    public function testDoesNotSupportJwtAccessToken(): void
    {
        $jwtToken = new JwtAccessToken('jwt.token.here');

        $supports = $this->validator->supports($jwtToken);

        $this->assertFalse($supports);
    }

    public function testValidateSuccess(): void
    {
        $opaqueToken = new OpaqueAccessToken('valid-opaque-token');

        $introspectionResponse = [
            'active' => true,
            'sub' => 'user123',
            'iss' => 'https://auth.example.com',
            'aud' => 'resource-server-audience',
            'exp' => time() + 3600,
            'iat' => time(),
            'scope' => 'read write',
            'client_id' => 'test-client-id',
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($introspectionResponse);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'https://auth.example.com/oauth/introspect',
                $this->callback(static function (mixed $options): bool {
                    if (!is_array($options) || !is_array($options['body'] ?? null)) {
                        return false;
                    }

                    return isset($options['body']['token'])
                        && $options['body']['token'] === 'valid-opaque-token'
                        && isset($options['body']['client_id'])
                        && $options['body']['client_id'] === 'test-client-id'
                        && isset($options['body']['client_secret'])
                        && $options['body']['client_secret'] === 'test-client-secret';
                }),
            )
            ->willReturn($response);

        $result = $this->validator->validate($opaqueToken);

        $this->assertInstanceOf(ValidatedAccessToken::class, $result);
        $this->assertSame('user123', $result->sub());
        $this->assertSame('https://auth.example.com', $result->iss());
        $this->assertSame('resource-server-audience', $result->aud());
        $this->assertSame('read write', $result->scope());
    }

    public function testValidateWithInvalidTokenType(): void
    {
        $jwtToken = new JwtAccessToken('jwt.token.here');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Token is not an opaque token');

        $this->validator->validate($jwtToken);
    }

    public function testValidateWithInactiveToken(): void
    {
        $opaqueToken = new OpaqueAccessToken('inactive-token');

        $introspectionResponse = [
            'active' => false,
            'sub' => 'user123',
            'exp' => time() - 3600, // Expired
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($introspectionResponse);

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Token is not active');

        $this->validator->validate($opaqueToken);
    }

    public function testValidateWithMissingActiveField(): void
    {
        $opaqueToken = new OpaqueAccessToken('token-without-active');

        $introspectionResponse = [
            'sub' => 'user123',
            'exp' => time() + 3600,
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($introspectionResponse);

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Token is not active');

        $this->validator->validate($opaqueToken);
    }

    public function testValidateWithHttpError(): void
    {
        $opaqueToken = new OpaqueAccessToken('error-token');

        $this->httpClient->method('request')
            ->willThrowException(new RuntimeException('HTTP request failed'));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Token introspection failed: HTTP request failed');

        $this->validator->validate($opaqueToken);
    }

    public function testValidateWithClientSecretBasicAuth(): void
    {
        // Create validator with basic auth client metadata
        $basicAuthClientMetadata = new ClientMetadata(
            clientId: 'basic-client-id',
            clientSecret: 'basic-client-secret',
            redirectUri: 'https://client.example.com/callback',
            defaultScopes: ['openid'],
            authenticationMethod: AuthenticationMethod::ClientSecretBasic,
        );

        $config = $this->createMock(Config::class);
        $config->method('issuerMetadata')->willReturn($this->issuerMetadata);
        $config->method('clientMetadata')->willReturn($basicAuthClientMetadata);

        $validator = new OpaqueAccessTokenValidator($config, $this->httpClient);

        $opaqueToken = new OpaqueAccessToken('basic-auth-token');

        $introspectionResponse = [
            'active' => true,
            'sub' => 'user123',
            'scope' => 'read',
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($introspectionResponse);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'https://auth.example.com/oauth/introspect',
                $this->callback(static function (mixed $options): bool {
                    if (
                        !is_array($options)
                        || !is_array($options['body'] ?? null)
                        || !is_array($options['auth_basic'] ?? null)
                    ) {
                        return false;
                    }

                    return isset($options['body']['token'])
                        && $options['body']['token'] === 'basic-auth-token'
                        && isset($options['auth_basic'][0])
                        && $options['auth_basic'][0] === 'basic-client-id'
                        && isset($options['auth_basic'][1])
                        && $options['auth_basic'][1] === 'basic-client-secret';
                }),
            )
            ->willReturn($response);

        $result = $validator->validate($opaqueToken);

        $this->assertInstanceOf(ValidatedAccessToken::class, $result);
        $this->assertSame('user123', $result->sub());
    }

    public function testValidateWithMinimalResponse(): void
    {
        $opaqueToken = new OpaqueAccessToken('minimal-token');

        // Minimal valid introspection response (only 'active' is required)
        $introspectionResponse = [
            'active' => true,
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($introspectionResponse);

        $this->httpClient->method('request')->willReturn($response);

        $result = $this->validator->validate($opaqueToken);

        $this->assertInstanceOf(ValidatedAccessToken::class, $result);
        $this->assertSame(['active' => true], $result->claims());
    }

    public function testValidateWithExtensiveResponse(): void
    {
        $opaqueToken = new OpaqueAccessToken('extensive-token');

        $introspectionResponse = [
            'active' => true,
            'sub' => 'user123',
            'iss' => 'https://auth.example.com',
            'aud' => ['resource-server-1', 'resource-server-2'],
            'exp' => time() + 3600,
            'iat' => time(),
            'nbf' => time() - 10,
            'scope' => 'read write admin',
            'client_id' => 'oauth-client-123',
            'username' => 'john.doe',
            'token_type' => 'Bearer',
            'jti' => 'token-identifier-123',
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($introspectionResponse);

        $this->httpClient->method('request')->willReturn($response);

        $result = $this->validator->validate($opaqueToken);

        $this->assertInstanceOf(ValidatedAccessToken::class, $result);
        $this->assertSame('user123', $result->sub());
        $this->assertSame('https://auth.example.com', $result->iss());
        $this->assertIsArray($result->aud());
        $this->assertContains('resource-server-1', $result->aud());
        $this->assertSame('read write admin', $result->scope());
        $this->assertSame($introspectionResponse, $result->claims());
    }

    /**
     * @param array<string, mixed> $responseData
     */
    #[DataProvider('invalidActiveValuesProvider')]
    public function testValidateWithInvalidActiveValues(array $responseData): void
    {
        $opaqueToken = new OpaqueAccessToken('invalid-active-token');

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($responseData);

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Token is not active');

        $this->validator->validate($opaqueToken);
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function invalidActiveValuesProvider(): array
    {
        return [
            'active is false' => [
                ['active' => false],
            ],
            'active is string true' => [
                ['active' => 'true'],
            ],
            'active is integer 1' => [
                ['active' => 1],
            ],
            'active is string false' => [
                ['active' => 'false'],
            ],
            'active is null' => [
                ['active' => null],
            ],
            'active is empty array' => [
                ['active' => []],
            ],
        ];
    }

    public function testValidateWithEmptyToken(): void
    {
        $opaqueToken = new OpaqueAccessToken('');

        $introspectionResponse = [
            'active' => false,
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($introspectionResponse);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'https://auth.example.com/oauth/introspect',
                $this->callback(static function (mixed $options): bool {
                    if (!is_array($options) || !is_array($options['body'] ?? null)) {
                        return false;
                    }

                    return isset($options['body']['token'])
                        && $options['body']['token'] === ''
                        && isset($options['body']['client_id'])
                        && $options['body']['client_id'] === 'test-client-id'
                        && isset($options['body']['client_secret'])
                        && $options['body']['client_secret'] === 'test-client-secret';
                }),
            )
            ->willReturn($response);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Token is not active');

        $this->validator->validate($opaqueToken);
    }

    public function testValidateWithNonArrayResponse(): void
    {
        $opaqueToken = new OpaqueAccessToken('invalid-response-token');

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')
            ->willThrowException(new RuntimeException('Invalid JSON response'));

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Token introspection failed: Invalid JSON response');

        $this->validator->validate($opaqueToken);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->config = $this->createMock(Config::class);
        $this->httpClient = $this->createMock(HttpClientInterface::class);

        $this->issuerMetadata = new IssuerMetadata([
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://auth.example.com/oauth/token',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
            'introspection_endpoint' => 'https://auth.example.com/oauth/introspect',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);

        $this->clientMetadata = new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            defaultScopes: ['openid', 'profile', 'email'],
            authenticationMethod: AuthenticationMethod::ClientSecretPost,
        );

        $this->config->method('issuerMetadata')->willReturn($this->issuerMetadata);
        $this->config->method('clientMetadata')->willReturn($this->clientMetadata);

        $this->validator = new OpaqueAccessTokenValidator($this->config, $this->httpClient);
    }
}
