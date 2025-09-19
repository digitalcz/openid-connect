<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

#[CoversClass(AuthenticationMethod::class)]
class AuthenticationMethodTest extends TestCase
{
    /**
     * @param array<string, mixed> $expectedOptions
     */
    #[DataProvider('asOptionsProvider')]
    public function testAsOptions(
        AuthenticationMethod $method,
        ClientMetadata $clientMetadata,
        array $expectedOptions,
    ): void {
        $options = $method->asOptions($clientMetadata);

        $this->assertSame($expectedOptions, $options);
    }

    /**
     * @return array<string, array{AuthenticationMethod, ClientMetadata, array<string, mixed>}>
     */
    public static function asOptionsProvider(): array
    {
        return [
            'ClientSecretPost with secret' => [
                AuthenticationMethod::ClientSecretPost,
                new ClientMetadata(clientId: 'test-client-id', clientSecret: 'test-client-secret'),
                [
                    'body' => [
                        'client_id' => 'test-client-id',
                        'client_secret' => 'test-client-secret',
                    ],
                ],
            ],
            'ClientSecretBasic with secret' => [
                AuthenticationMethod::ClientSecretBasic,
                new ClientMetadata(clientId: 'test-client-id', clientSecret: 'test-client-secret'),
                [
                    'auth_basic' => ['test-client-id', 'test-client-secret'],
                ],
            ],
            'ClientSecretBasic without secret' => [
                AuthenticationMethod::ClientSecretBasic,
                new ClientMetadata(clientId: 'test-client-id', clientSecret: null),
                [
                    'auth_basic' => ['test-client-id', ''],
                ],
            ],
            'None (public client)' => [
                AuthenticationMethod::None,
                new ClientMetadata(clientId: 'test-client-id', clientSecret: null),
                [
                    'body' => [
                        'client_id' => 'test-client-id',
                    ],
                ],
            ],
        ];
    }

    public function testEnumCases(): void
    {
        $cases = AuthenticationMethod::cases();

        $this->assertCount(5, $cases);
        $this->assertContains(AuthenticationMethod::ClientSecretBasic, $cases);
        $this->assertContains(AuthenticationMethod::ClientSecretPost, $cases);
        $this->assertContains(AuthenticationMethod::ClientSecretJwt, $cases);
        $this->assertContains(AuthenticationMethod::PrivateKeyJwt, $cases);
        $this->assertContains(AuthenticationMethod::None, $cases);
    }

    public function testJwtAuthenticationMethodsThrowException(): void
    {
        $clientMetadata = new ClientMetadata(clientId: 'test-client-id');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            'JWT authentication methods require token endpoint URL. Use ClientMetadata::applyCredentials() instead.',
        );

        AuthenticationMethod::ClientSecretJwt->asOptions($clientMetadata);
    }

    public function testPrivateKeyJwtAuthenticationMethodThrowsException(): void
    {
        $clientMetadata = new ClientMetadata(clientId: 'test-client-id');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            'JWT authentication methods require token endpoint URL. Use ClientMetadata::applyCredentials() instead.',
        );

        AuthenticationMethod::PrivateKeyJwt->asOptions($clientMetadata);
    }
}
