<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\TestCase;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use RuntimeException;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

#[CoversClass(AuthorizationCode::class)]
class AuthorizationCodeTest extends TestCase
{
    private Config&MockObject $config;
    private HttpClientInterface&MockObject $httpClient;
    private IdTokenValidator&MockObject $validator;
    private IssuerMetadata $issuerMetadata;
    private ClientMetadata $clientMetadata;
    private AuthorizationCode $authorizationCode;

    public function testConstructor(): void
    {
        $authCode = new AuthorizationCode($this->config, $this->httpClient, $this->validator);

        $this->assertInstanceOf(AuthorizationCode::class, $authCode);
    }

    public function testCreateAuthorizationUrlWithDefaults(): void
    {
        $url = $this->authorizationCode->createAuthorizationUrl();

        $expectedParams = [
            'client_id' => 'test-client-id',
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'redirect_uri' => 'https://client.example.com/callback',
        ];

        $this->assertStringStartsWith('https://auth.example.com/oauth/authorize', $url);

        foreach ($expectedParams as $key => $value) {
            $this->assertStringContainsString($key . '=' . urlencode($value), $url);
        }
    }

    public function testCreateAuthorizationUrlWithCustomParams(): void
    {
        $customParams = [
            'state' => 'random-state-value',
            'nonce' => 'random-nonce-value',
            'prompt' => 'consent',
        ];

        $url = $this->authorizationCode->createAuthorizationUrl($customParams);

        foreach ($customParams as $key => $value) {
            $this->assertStringContainsString($key . '=' . urlencode($value), $url);
        }
    }

    public function testCreateAuthorizationUrlOverrideDefaults(): void
    {
        $overrideParams = [
            'client_id' => 'custom-client-id',
            'response_type' => 'id_token',
            'scope' => 'openid',
            'redirect_uri' => 'https://custom.example.com/callback',
        ];

        $url = $this->authorizationCode->createAuthorizationUrl($overrideParams);

        foreach ($overrideParams as $key => $value) {
            $this->assertStringContainsString($key . '=' . urlencode($value), $url);
        }

        // Should not contain default values when overridden
        $this->assertStringNotContainsString('test-client-id', $url);
        $this->assertStringNotContainsString('openid%20profile%20email', $url);
    }

    public function testCreateAuthorizationUrlWithoutRedirectUri(): void
    {
        // Create fresh mocks to override the setup
        $config = $this->createMock(Config::class);
        $issuerMetadata = $this->createRealIssuerMetadata();

        // Create client metadata without redirect URI (defaults to null)
        $clientMetadataWithoutRedirect = new ClientMetadata(clientId: 'test-client-id', clientSecret: 'test-secret');

        $config->method('issuerMetadata')->willReturn($issuerMetadata);
        $config->method('clientMetadata')->willReturn($clientMetadataWithoutRedirect);

        // Create a new instance with the fresh config
        $authCode = new AuthorizationCode($config, $this->httpClient, $this->validator);

        $url = $authCode->createAuthorizationUrl();

        // Should not contain redirect_uri when not configured (clientMetadata.redirectUri() is null)
        $this->assertStringNotContainsString('redirect_uri=', $url);
    }

    public function testFetchTokensSuccess(): void
    {
        $authorizationCode = 'test-auth-code';
        $nonce = 'test-nonce';

        $tokenResponse = [
            'access_token' => 'access-token-123',
            'refresh_token' => 'refresh-token-456',
            'id_token' => $this->createValidJwtString(),
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($tokenResponse);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'https://auth.example.com/oauth/token',
                $this->callback(static fn ($options) => $options['body']['grant_type'] === 'authorization_code'
                        && $options['body']['code'] === $authorizationCode
                        && $options['body']['redirect_uri'] === 'https://client.example.com/callback'),
            )
            ->willReturn($response);

        $this->validator->expects($this->once())
            ->method('validate')
            ->with($this->isInstanceOf(IdToken::class), $nonce);

        $tokens = $this->authorizationCode->fetchTokens($authorizationCode, $nonce);

        $this->assertInstanceOf(Tokens::class, $tokens);
        $this->assertSame('access-token-123', (string) $tokens->accessToken());
        $this->assertNotNull($tokens->refreshToken());
        $this->assertNotNull($tokens->idToken());
    }

    public function testFetchTokensWithoutIdToken(): void
    {
        $authorizationCode = 'test-auth-code';

        $tokenResponse = [
            'access_token' => 'access-token-123',
            'refresh_token' => 'refresh-token-456',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($tokenResponse);

        $this->httpClient->method('request')->willReturn($response);

        // Validator should not be called when there's no ID token
        $this->validator->expects($this->never())->method('validate');

        $tokens = $this->authorizationCode->fetchTokens($authorizationCode);

        $this->assertInstanceOf(Tokens::class, $tokens);
        $this->assertNull($tokens->idToken());
    }

    public function testFetchTokensHttpError(): void
    {
        $authorizationCode = 'test-auth-code';

        $this->httpClient->method('request')
            ->willThrowException(new RuntimeException('HTTP request failed'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('HTTP request failed');

        $this->authorizationCode->fetchTokens($authorizationCode);
    }

    public function testRefreshTokenSuccess(): void
    {
        $originalTokens = $this->createTokensWithRefreshToken();

        $refreshResponse = [
            'access_token' => 'new-access-token-789',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($refreshResponse);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'https://auth.example.com/oauth/token',
                $this->callback(static fn ($options) => $options['body']['grant_type'] === 'refresh_token'
                        && (string) $options['body']['refresh_token'] === 'refresh-token-456'),
            )
            ->willReturn($response);

        $newTokens = $this->authorizationCode->refreshToken($originalTokens);

        $this->assertInstanceOf(Tokens::class, $newTokens);
        $this->assertSame('new-access-token-789', (string) $newTokens->accessToken());
        // Original refresh token should be preserved if not rotated
        $this->assertSame('refresh-token-456', (string) $newTokens->refreshToken());
    }

    public function testRefreshTokenWithoutRefreshToken(): void
    {
        $tokensWithoutRefresh = $this->createTokensWithoutRefreshToken();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot refresh tokens without a refresh token');

        $this->authorizationCode->refreshToken($tokensWithoutRefresh);
    }

    public function testFetchUserinfoSuccess(): void
    {
        $tokens = $this->createTokensWithIdToken();

        $userinfoResponse = [
            'sub' => 'user123',
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'picture' => 'https://example.com/avatar.jpg',
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($userinfoResponse);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with(
                'GET',
                'https://auth.example.com/userinfo',
                ['auth_bearer' => 'access-token-123'],
            )
            ->willReturn($response);

        $userinfo = $this->authorizationCode->fetchUserinfo($tokens);

        $this->assertInstanceOf(Userinfo::class, $userinfo);
        $this->assertSame('user123', $userinfo->sub());
    }

    public function testFetchUserinfoWithoutAccessToken(): void
    {
        $tokensWithoutAccess = $this->createTokensWithoutAccessToken();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot fetch userinfo without an access token');

        $this->authorizationCode->fetchUserinfo($tokensWithoutAccess);
    }

    public function testFetchUserinfoSubMismatch(): void
    {
        $tokens = $this->createTokensWithIdToken();

        $userinfoResponse = [
            'sub' => 'different-user-id', // Different from ID token
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($userinfoResponse);

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Userinfo sub does not match id_token sub');

        $this->authorizationCode->fetchUserinfo($tokens);
    }

    public function testFetchUserinfoWithoutIdToken(): void
    {
        $tokensWithoutIdToken = $this->createTokensWithoutIdToken();

        $userinfoResponse = [
            'sub' => 'user123',
            'name' => 'John Doe',
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($userinfoResponse);

        $this->httpClient->method('request')->willReturn($response);

        // Should not throw exception when there's no ID token to compare
        $userinfo = $this->authorizationCode->fetchUserinfo($tokensWithoutIdToken);

        $this->assertInstanceOf(Userinfo::class, $userinfo);
        $this->assertSame('user123', $userinfo->sub());
    }

    /**
     * @param array<string, string> $params
     */
    #[DataProvider('authorizationUrlParamsProvider')]
    public function testCreateAuthorizationUrlWithVariousParams(array $params, string $expectedContains): void
    {
        $url = $this->authorizationCode->createAuthorizationUrl($params);

        $this->assertStringContainsString($expectedContains, $url);
    }

    /**
     * @return array<string, array{array<string, string>, string}>
     */
    public static function authorizationUrlParamsProvider(): array
    {
        return [
            'with state parameter' => [
                ['state' => 'abc123'],
                'state=abc123',
            ],
            'with nonce parameter' => [
                ['nonce' => 'xyz789'],
                'nonce=xyz789',
            ],
            'with prompt parameter' => [
                ['prompt' => 'login'],
                'prompt=login',
            ],
            'with max_age parameter' => [
                ['max_age' => '3600'],
                'max_age=3600',
            ],
            'with code_challenge (PKCE)' => [
                ['code_challenge' => 'code_challenge_value', 'code_challenge_method' => 'S256'],
                'code_challenge=code_challenge_value',
            ],
        ];
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->config = $this->createMock(Config::class);
        $this->httpClient = $this->createMock(HttpClientInterface::class);
        $this->validator = $this->createMock(IdTokenValidator::class);

        $this->issuerMetadata = $this->createRealIssuerMetadata();
        $this->clientMetadata = $this->createRealClientMetadata();

        $this->config->method('issuerMetadata')->willReturn($this->issuerMetadata);
        $this->config->method('clientMetadata')->willReturn($this->clientMetadata);

        $this->authorizationCode = new AuthorizationCode($this->config, $this->httpClient, $this->validator);
    }

    private function createRealIssuerMetadata(): IssuerMetadata
    {
        return new IssuerMetadata([
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://auth.example.com/oauth/token',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);
    }

    private function createRealClientMetadata(): ClientMetadata
    {
        return new ClientMetadata(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://client.example.com/callback',
            defaultScopes: ['openid', 'profile', 'email'],
            authenticationMethod: AuthenticationMethod::ClientSecretPost,
        );
    }

    private function createValidJwtString(): string
    {
        $header = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode([
            'iss' => 'https://auth.example.com',
            'sub' => 'user123',
            'aud' => 'test-client-id',
            'exp' => time() + 3600,
            'iat' => time(),
        ]));
        $signature = base64_encode('fake-signature');

        return $header . '.' . $payload . '.' . $signature;
    }

    private function createTokensWithRefreshToken(): Tokens
    {
        return Tokens::fromTokenResponse([
            'access_token' => 'access-token-123',
            'refresh_token' => 'refresh-token-456',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);
    }

    private function createTokensWithoutRefreshToken(): Tokens
    {
        return Tokens::fromTokenResponse([
            'access_token' => 'access-token-123',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);
    }

    private function createTokensWithIdToken(): Tokens
    {
        return Tokens::fromTokenResponse([
            'access_token' => 'access-token-123',
            'id_token' => $this->createValidJwtString(),
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);
    }

    private function createTokensWithoutAccessToken(): Tokens
    {
        return Tokens::fromTokenResponse([
            'id_token' => $this->createValidJwtString(),
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);
    }

    private function createTokensWithoutIdToken(): Tokens
    {
        return Tokens::fromTokenResponse([
            'access_token' => 'access-token-123',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);
    }
}
