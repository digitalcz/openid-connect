<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DigitalCz\OpenIDConnect\Oidc;
use DigitalCz\OpenIDConnect\OidcFactory;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

#[CoversClass(Oidc::class)]
#[CoversClass(OidcFactory::class)]
class OidcIntegrationTest extends TestCase
{
    public function testBackChannelLogoutMethodExists(): void
    {
        $httpClient = new MockHttpClient([
            new MockResponse(json_encode($this->createDiscoveryDocument())),
            new MockResponse(json_encode($this->createSampleJwks())),
        ]);

        $oidc = OidcFactory::create(
            httpClient: $httpClient,
            issuer: 'https://example.com',
            clientId: 'test-client-id',
            clientSecret: 'test-secret',
        );

        $handler = $oidc->backChannelLogout();

        $this->assertInstanceOf(BackChannelLogoutHandler::class, $handler);
    }

    public function testBackChannelLogoutWithConfiguration(): void
    {
        $httpClient = new MockHttpClient([
            new MockResponse(json_encode($this->createDiscoveryDocument())),
            new MockResponse(json_encode($this->createSampleJwks())),
        ]);

        $oidc = OidcFactory::create(
            httpClient: $httpClient,
            issuer: 'https://example.com',
            clientId: 'test-client-id',
            clientSecret: 'test-secret',
            backchannelLogoutUri: 'https://rp.example.com/logout/backchannel',
            backchannelLogoutSessionRequired: true,
        );

        $handler = $oidc->backChannelLogout();

        $this->assertInstanceOf(BackChannelLogoutHandler::class, $handler);
    }

    /**
     * @return array<string, mixed>
     */
    private function createDiscoveryDocument(): array
    {
        return [
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/authorize',
            'token_endpoint' => 'https://example.com/token',
            'jwks_uri' => 'https://example.com/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
        ];
    }
}
