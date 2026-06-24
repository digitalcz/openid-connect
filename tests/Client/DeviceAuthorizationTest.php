<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DateTimeImmutable;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Exception\DeviceAuthorizationDeniedException;
use DigitalCz\OpenIDConnect\Exception\DeviceAuthorizationException;
use DigitalCz\OpenIDConnect\Exception\DeviceAuthorizationExpiredException;
use DigitalCz\OpenIDConnect\Exception\DeviceAuthorizationPendingException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;
use DigitalCz\OpenIDConnect\Exception\SlowDownException;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use UnexpectedValueException;

#[CoversClass(DeviceAuthorization::class)]
#[CoversClass(DeviceAuthorizationResponse::class)]
#[CoversClass(DeviceAuthorizationException::class)]
#[CoversClass(DeviceAuthorizationPendingException::class)]
#[CoversClass(SlowDownException::class)]
#[CoversClass(DeviceAuthorizationExpiredException::class)]
#[CoversClass(DeviceAuthorizationDeniedException::class)]
class DeviceAuthorizationTest extends TestCase
{
    private Config&MockObject $config;
    private HttpClientInterface&MockObject $httpClient;
    private ClockInterface&MockObject $clock;

    /** @var list<int> */
    private array $sleeps = [];

    private DeviceAuthorization $deviceAuthorization;

    public function testRequestDeviceAuthorizationSuccess(): void
    {
        $responseData = [
            'device_code' => 'device-code-abc',
            'user_code' => 'WDJB-MJHT',
            'verification_uri' => 'https://auth.example.com/device',
            'verification_uri_complete' => 'https://auth.example.com/device?user_code=WDJB-MJHT',
            'expires_in' => 1800,
            'interval' => 5,
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn($responseData);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'https://auth.example.com/oauth/device_authorization',
                $this->callback(static fn ($options): bool => is_array($options)
                        && isset($options['body'])
                        && is_array($options['body'])
                        && $options['body']['scope'] === 'openid profile email'
                        && $options['body']['client_id'] === 'test-client-id'
                        && $options['body']['client_secret'] === 'test-client-secret'),
            )
            ->willReturn($response);

        $result = $this->deviceAuthorization->requestDeviceAuthorization();

        $this->assertSame('device-code-abc', $result->deviceCode());
        $this->assertSame('WDJB-MJHT', $result->userCode());
        $this->assertSame('https://auth.example.com/device', $result->verificationUri());
        $this->assertSame(
            'https://auth.example.com/device?user_code=WDJB-MJHT',
            $result->verificationUriComplete(),
        );
        $this->assertSame(1800, $result->expiresIn());
        $this->assertSame(5, $result->interval());
    }

    public function testRequestDeviceAuthorizationAllowsCustomScope(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn([
            'device_code' => 'd',
            'user_code' => 'u',
            'verification_uri' => 'https://auth.example.com/device',
            'expires_in' => 600,
        ]);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'https://auth.example.com/oauth/device_authorization',
                $this->callback(static fn ($options): bool => is_array($options)
                    && is_array($options['body'])
                    && $options['body']['scope'] === 'custom'),
            )
            ->willReturn($response);

        $result = $this->deviceAuthorization->requestDeviceAuthorization(['scope' => 'custom']);

        $this->assertSame('d', $result->deviceCode());
        $this->assertNull($result->verificationUriComplete());
        $this->assertNull($result->interval());
    }

    public function testRequestDeviceAuthorizationValidatesDeviceCode(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn([
            'user_code' => 'u',
            'verification_uri' => 'https://auth.example.com/device',
            'expires_in' => 600,
        ]);

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('device_code');

        $this->deviceAuthorization->requestDeviceAuthorization();
    }

    public function testRequestDeviceAuthorizationValidatesUserCode(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn([
            'device_code' => 'd',
            'verification_uri' => 'https://auth.example.com/device',
            'expires_in' => 600,
        ]);

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('user_code');

        $this->deviceAuthorization->requestDeviceAuthorization();
    }

    public function testRequestDeviceAuthorizationValidatesVerificationUri(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn([
            'device_code' => 'd',
            'user_code' => 'u',
            'expires_in' => 600,
        ]);

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('verification_uri');

        $this->deviceAuthorization->requestDeviceAuthorization();
    }

    public function testRequestDeviceAuthorizationValidatesExpiresIn(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn([
            'device_code' => 'd',
            'user_code' => 'u',
            'verification_uri' => 'https://auth.example.com/device',
        ]);

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('expires_in');

        $this->deviceAuthorization->requestDeviceAuthorization();
    }

    public function testRequestDeviceAuthorizationWrapsHttpClientExceptionInNetworkException(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willThrowException($this->createMock(ServerExceptionInterface::class));

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(NetworkException::class);
        $this->expectExceptionMessage('Device authorization request failed:');

        $this->deviceAuthorization->requestDeviceAuthorization();
    }

    public function testFetchTokensWrapsHttpClientExceptionInNetworkException(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willThrowException($this->createMock(TransportExceptionInterface::class));

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(NetworkException::class);
        $this->expectExceptionMessage('Device token request failed:');

        $this->deviceAuthorization->fetchTokens('device-code');
    }

    public function testFetchTokensSuccess(): void
    {
        $tokenResponse = [
            'access_token' => 'access-token-123',
            'refresh_token' => 'refresh-token-456',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->with(false)->willReturn($tokenResponse);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'https://auth.example.com/oauth/token',
                $this->callback(static fn ($options): bool => is_array($options)
                        && is_array($options['body'])
                        && $options['body']['grant_type'] === 'urn:ietf:params:oauth:grant-type:device_code'
                        && $options['body']['device_code'] === 'device-code-abc'),
            )
            ->willReturn($response);

        $tokens = $this->deviceAuthorization->fetchTokens('device-code-abc');

        $this->assertInstanceOf(Tokens::class, $tokens);
        $this->assertSame('access-token-123', (string) $tokens->accessToken());
        $this->assertSame('Bearer', $tokens->tokenType());
        $this->assertSame(3600, $tokens->expiresIn());
    }

    public function testFetchTokensThrowsPending(): void
    {
        $this->mockTokenResponse(['error' => 'authorization_pending']);

        $this->expectException(DeviceAuthorizationPendingException::class);

        $this->deviceAuthorization->fetchTokens('device-code');
    }

    public function testFetchTokensThrowsSlowDown(): void
    {
        $this->mockTokenResponse(['error' => 'slow_down']);

        $this->expectException(SlowDownException::class);

        $this->deviceAuthorization->fetchTokens('device-code');
    }

    public function testFetchTokensThrowsExpired(): void
    {
        $this->mockTokenResponse([
            'error' => 'expired_token',
            'error_description' => 'Device code expired',
        ]);

        try {
            $this->deviceAuthorization->fetchTokens('device-code');
            $this->fail('Expected DeviceAuthorizationExpiredException');
        } catch (DeviceAuthorizationExpiredException $e) {
            $this->assertSame('expired_token', $e->error());
            $this->assertSame('Device code expired', $e->errorDescription());
            $this->assertSame('Device code expired', $e->getMessage());
        }
    }

    public function testFetchTokensThrowsDenied(): void
    {
        $this->mockTokenResponse(['error' => 'access_denied']);

        $this->expectException(DeviceAuthorizationDeniedException::class);
        $this->expectExceptionMessage('access_denied');

        $this->deviceAuthorization->fetchTokens('device-code');
    }

    public function testFetchTokensThrowsGenericForUnknownError(): void
    {
        $this->mockTokenResponse([
            'error' => 'invalid_grant',
            'error_description' => 'Bad code',
        ]);

        try {
            $this->deviceAuthorization->fetchTokens('device-code');
            $this->fail('Expected DeviceAuthorizationException');
        } catch (DeviceAuthorizationDeniedException | DeviceAuthorizationExpiredException | DeviceAuthorizationPendingException | SlowDownException $e) {
            $this->fail('Should not map unknown error to a specific subclass: ' . $e::class);
        } catch (DeviceAuthorizationException $e) {
            $this->assertSame('invalid_grant', $e->error());
            $this->assertSame('Bad code', $e->errorDescription());
        }
    }

    public function testPollForTokensReturnsAfterPending(): void
    {
        $this->fixedClock(1000);

        $pendingResponse = $this->createMock(ResponseInterface::class);
        $pendingResponse->method('toArray')->with(false)->willReturn(['error' => 'authorization_pending']);

        $successResponse = $this->createMock(ResponseInterface::class);
        $successResponse->method('toArray')->with(false)->willReturn([
            'access_token' => 'final-token',
            'token_type' => 'Bearer',
        ]);

        $this->httpClient->expects($this->exactly(2))
            ->method('request')
            ->willReturnOnConsecutiveCalls($pendingResponse, $successResponse);

        $deviceResponse = new DeviceAuthorizationResponse(
            deviceCode: 'dc',
            userCode: 'uc',
            verificationUri: 'https://auth.example.com/device',
            expiresIn: 600,
            interval: 3,
        );

        $tokens = $this->deviceAuthorization->pollForTokens($deviceResponse);

        $this->assertSame('final-token', (string) $tokens->accessToken());
        $this->assertSame([3], $this->sleeps);
    }

    public function testPollForTokensIncreasesIntervalOnSlowDown(): void
    {
        $this->fixedClock(1000);

        $slowDown = $this->createMock(ResponseInterface::class);
        $slowDown->method('toArray')->with(false)->willReturn(['error' => 'slow_down']);

        $pending = $this->createMock(ResponseInterface::class);
        $pending->method('toArray')->with(false)->willReturn(['error' => 'authorization_pending']);

        $success = $this->createMock(ResponseInterface::class);
        $success->method('toArray')->with(false)->willReturn([
            'access_token' => 'token',
            'token_type' => 'Bearer',
        ]);

        $this->httpClient->expects($this->exactly(3))
            ->method('request')
            ->willReturnOnConsecutiveCalls($slowDown, $pending, $success);

        $deviceResponse = new DeviceAuthorizationResponse(
            deviceCode: 'dc',
            userCode: 'uc',
            verificationUri: 'https://auth.example.com/device',
            expiresIn: 600,
            interval: 5,
        );

        $tokens = $this->deviceAuthorization->pollForTokens($deviceResponse);

        $this->assertSame('token', (string) $tokens->accessToken());
        // slow_down bumps interval from 5 -> 10, then pending keeps it at 10.
        $this->assertSame([10, 10], $this->sleeps);
    }

    public function testPollForTokensUsesDefaultIntervalWhenMissing(): void
    {
        $this->fixedClock(1000);

        $pending = $this->createMock(ResponseInterface::class);
        $pending->method('toArray')->with(false)->willReturn(['error' => 'authorization_pending']);

        $success = $this->createMock(ResponseInterface::class);
        $success->method('toArray')->with(false)->willReturn(['access_token' => 'abc']);

        $this->httpClient->expects($this->exactly(2))
            ->method('request')
            ->willReturnOnConsecutiveCalls($pending, $success);

        $deviceResponse = new DeviceAuthorizationResponse(
            deviceCode: 'dc',
            userCode: 'uc',
            verificationUri: 'https://auth.example.com/device',
            expiresIn: 600,
        );

        $this->deviceAuthorization->pollForTokens($deviceResponse);

        $this->assertSame([5], $this->sleeps);
    }

    public function testPollForTokensRethrowsDenied(): void
    {
        $this->fixedClock(1000);
        $this->mockTokenResponse(['error' => 'access_denied']);

        $deviceResponse = new DeviceAuthorizationResponse(
            deviceCode: 'dc',
            userCode: 'uc',
            verificationUri: 'https://auth.example.com/device',
            expiresIn: 600,
            interval: 5,
        );

        $this->expectException(DeviceAuthorizationDeniedException::class);

        $this->deviceAuthorization->pollForTokens($deviceResponse);
    }

    public function testPollForTokensExpiresWhenDeadlineReached(): void
    {
        $pending = $this->createMock(ResponseInterface::class);
        $pending->method('toArray')->with(false)->willReturn(['error' => 'authorization_pending']);

        $this->httpClient->method('request')->willReturn($pending);

        // Clock advances so the second poll would exceed the 10s lifetime.
        $this->clock->method('now')->willReturnOnConsecutiveCalls(
            new DateTimeImmutable('@1000'), // initial deadline calc
            new DateTimeImmutable('@1006'), // first check: 1006 + 5 > 1010 -> expired
        );

        $deviceResponse = new DeviceAuthorizationResponse(
            deviceCode: 'dc',
            userCode: 'uc',
            verificationUri: 'https://auth.example.com/device',
            expiresIn: 10,
            interval: 5,
        );

        $this->expectException(DeviceAuthorizationExpiredException::class);

        $this->deviceAuthorization->pollForTokens($deviceResponse);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->config = $this->createMock(Config::class);
        $this->httpClient = $this->createMock(HttpClientInterface::class);
        $this->clock = $this->createMock(ClockInterface::class);

        $this->config->method('issuerMetadata')->willReturn($this->createRealIssuerMetadata());
        $this->config->method('clientMetadata')->willReturn($this->createRealClientMetadata());

        $this->sleeps = [];
        $sleeps = &$this->sleeps;

        $this->deviceAuthorization = new DeviceAuthorization(
            $this->config,
            $this->httpClient,
            $this->clock,
            static function (int $seconds) use (&$sleeps): void {
                $sleeps[] = $seconds;
            },
        );
    }

    private function fixedClock(int $timestamp): void
    {
        $this->clock->method('now')->willReturn(new DateTimeImmutable('@' . $timestamp));
    }

    /**
     * @param array<string, mixed> $data
     */
    private function mockTokenResponse(array $data): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->with(false)->willReturn($data);
        $this->httpClient->method('request')->willReturn($response);
    }

    private function createRealIssuerMetadata(): IssuerMetadata
    {
        return new IssuerMetadata([
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://auth.example.com/oauth/token',
            'device_authorization_endpoint' => 'https://auth.example.com/oauth/device_authorization',
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
            defaultScopes: ['openid', 'profile', 'email'],
        );
    }
}
