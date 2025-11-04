<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Config;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(IssuerMetadata::class)]
class IssuerMetadataTest extends TestCase
{
    public function testConstructor(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertInstanceOf(IssuerMetadata::class, $issuerMetadata);
    }

    public function testIssuer(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame('https://auth.example.com', $issuerMetadata->issuer());
    }

    public function testAuthorizationEndpoint(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            'https://auth.example.com/oauth/authorize',
            $issuerMetadata->authorizationEndpoint(),
        );
    }

    public function testTokenEndpoint(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            'https://auth.example.com/oauth/token',
            $issuerMetadata->tokenEndpoint(),
        );
    }

    public function testJwksUri(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            'https://auth.example.com/.well-known/jwks.json',
            $issuerMetadata->jwksUri(),
        );
    }

    public function testUserinfoEndpoint(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            'https://auth.example.com/userinfo',
            $issuerMetadata->userinfoEndpoint(),
        );
    }

    public function testEndSessionEndpoint(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            'https://auth.example.com/logout',
            $issuerMetadata->endSessionEndpoint(),
        );
    }

    public function testIntrospectionEndpoint(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            'https://auth.example.com/introspect',
            $issuerMetadata->introspectionEndpoint(),
        );
    }

    public function testResponseTypesSupported(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            ['code', 'token', 'id_token'],
            $issuerMetadata->responseTypesSupported(),
        );
    }

    public function testSubjectTypesSupported(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            ['public', 'pairwise'],
            $issuerMetadata->subjectTypesSupported(),
        );
    }

    public function testIdTokenSigningAlgValuesSupported(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            ['RS256', 'ES256'],
            $issuerMetadata->idTokenSigningAlgValuesSupported(),
        );
    }

    public function testTokenEndpointAuthSigningAlgValuesSupported(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            ['RS256', 'HS256'],
            $issuerMetadata->tokenEndpointAuthSigningAlgValuesSupported(),
        );
    }

    public function testScopesSupported(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            ['openid', 'profile', 'email', 'offline_access'],
            $issuerMetadata->scopesSupported(),
        );
    }

    public function testClaimsSupported(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame(
            ['sub', 'name', 'email', 'picture'],
            $issuerMetadata->claimsSupported(),
        );
    }

    public function testAll(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertSame($metadata, $issuerMetadata->claims());
    }

    public function testClaimsTraitIntegration(): void
    {
        $metadata = [
            'issuer' => 'https://test.com',
            'custom_boolean' => true,
            'custom_integer' => 42,
            'custom_strings' => ['value1', 'value2'],
        ];
        $issuerMetadata = new IssuerMetadata($metadata);

        // Test ClaimsTrait methods
        $this->assertTrue($issuerMetadata->has('issuer'));
        $this->assertFalse($issuerMetadata->has('nonexistent'));

        $this->assertSame('https://test.com', $issuerMetadata->string('issuer'));
        $this->assertTrue($issuerMetadata->boolean('custom_boolean'));
        $this->assertSame(42, $issuerMetadata->integer('custom_integer'));
        $this->assertSame(['value1', 'value2'], $issuerMetadata->strings('custom_strings'));
    }

    public function testWithGoogleMetadata(): void
    {
        // Test with Google's actual OpenID Connect metadata structure
        $googleMetadata = [
            'issuer' => 'https://accounts.google.com',
            'authorization_endpoint' => 'https://accounts.google.com/o/oauth2/v2/auth',
            'token_endpoint' => 'https://oauth2.googleapis.com/token',
            'userinfo_endpoint' => 'https://openidconnect.googleapis.com/v1/userinfo',
            'revocation_endpoint' => 'https://oauth2.googleapis.com/revoke',
            'jwks_uri' => 'https://www.googleapis.com/oauth2/v3/certs',
            'response_types_supported' => ['code', 'token', 'id_token', 'code token', 'code id_token', 'token id_token', 'code token id_token', 'none'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => ['openid', 'email', 'profile'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic'],
            'claims_supported' => ['aud', 'email', 'email_verified', 'exp', 'family_name', 'given_name', 'iat', 'iss', 'locale', 'name', 'picture', 'sub'],
            'code_challenge_methods_supported' => ['plain', 'S256'],
        ];

        $issuerMetadata = new IssuerMetadata($googleMetadata);

        $this->assertSame('https://accounts.google.com', $issuerMetadata->issuer());
        $this->assertSame('https://accounts.google.com/o/oauth2/v2/auth', $issuerMetadata->authorizationEndpoint());
        $this->assertSame('https://oauth2.googleapis.com/token', $issuerMetadata->tokenEndpoint());
        $this->assertSame('https://www.googleapis.com/oauth2/v3/certs', $issuerMetadata->jwksUri());
        $this->assertSame(['openid', 'email', 'profile'], $issuerMetadata->scopesSupported());
    }

    public function testWithMinimalMetadata(): void
    {
        // Test with minimal required OIDC metadata
        $minimalMetadata = [
            'issuer' => 'https://minimal.example.com',
            'authorization_endpoint' => 'https://minimal.example.com/auth',
            'token_endpoint' => 'https://minimal.example.com/token',
            'jwks_uri' => 'https://minimal.example.com/jwks',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $issuerMetadata = new IssuerMetadata($minimalMetadata);

        $this->assertSame('https://minimal.example.com', $issuerMetadata->issuer());
        $this->assertSame(['code'], $issuerMetadata->responseTypesSupported());
        $this->assertSame(['public'], $issuerMetadata->subjectTypesSupported());
        $this->assertSame(['RS256'], $issuerMetadata->idTokenSigningAlgValuesSupported());
    }

    public function testWithExtensiveEndpoints(): void
    {
        $metadata = [
            'issuer' => 'https://comprehensive.example.com',
            'authorization_endpoint' => 'https://comprehensive.example.com/oauth/authorize',
            'token_endpoint' => 'https://comprehensive.example.com/oauth/token',
            'userinfo_endpoint' => 'https://comprehensive.example.com/userinfo',
            'end_session_endpoint' => 'https://comprehensive.example.com/logout',
            'introspection_endpoint' => 'https://comprehensive.example.com/introspect',
            'jwks_uri' => 'https://comprehensive.example.com/.well-known/jwks.json',
            'response_types_supported' => ['code', 'code id_token', 'code token', 'code id_token token'],
            'subject_types_supported' => ['public', 'pairwise'],
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256', 'PS256'],
            'token_endpoint_auth_signing_alg_values_supported' => ['RS256', 'ES256', 'HS256'],
            'scopes_supported' => ['openid', 'profile', 'email', 'address', 'phone', 'offline_access'],
            'claims_supported' => ['sub', 'name', 'given_name', 'family_name', 'email', 'email_verified', 'picture', 'address', 'phone_number'],
        ];

        $issuerMetadata = new IssuerMetadata($metadata);

        // Verify all endpoints are accessible
        $this->assertStringContainsString('comprehensive.example.com', $issuerMetadata->issuer());
        $this->assertStringContainsString('authorize', $issuerMetadata->authorizationEndpoint());
        $this->assertStringContainsString('token', $issuerMetadata->tokenEndpoint());
        $this->assertStringContainsString('userinfo', $issuerMetadata->userinfoEndpoint());
        $this->assertStringContainsString('logout', $issuerMetadata->endSessionEndpoint());
        $this->assertStringContainsString('introspect', $issuerMetadata->introspectionEndpoint());
        $this->assertStringContainsString('jwks', $issuerMetadata->jwksUri());

        // Verify array properties have expected content
        $this->assertContains('code', $issuerMetadata->responseTypesSupported());
        $this->assertContains('pairwise', $issuerMetadata->subjectTypesSupported());
        $this->assertContains('ES256', $issuerMetadata->idTokenSigningAlgValuesSupported());
        $this->assertContains('offline_access', $issuerMetadata->scopesSupported());
        $this->assertContains('email_verified', $issuerMetadata->claimsSupported());
    }

    /**
     * @return array<string, mixed>
     */
    private function createSampleMetadata(): array
    {
        return [
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/oauth/authorize',
            'token_endpoint' => 'https://auth.example.com/oauth/token',
            'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
            'end_session_endpoint' => 'https://auth.example.com/logout',
            'introspection_endpoint' => 'https://auth.example.com/introspect',
            'response_types_supported' => ['code', 'token', 'id_token'],
            'subject_types_supported' => ['public', 'pairwise'],
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256'],
            'token_endpoint_auth_signing_alg_values_supported' => ['RS256', 'HS256'],
            'scopes_supported' => ['openid', 'profile', 'email', 'offline_access'],
            'claims_supported' => ['sub', 'name', 'email', 'picture'],
        ];
    }

    public function testBackchannelLogoutSupported(): void
    {
        $metadata = $this->createSampleMetadata();
        $metadata['backchannel_logout_supported'] = true;
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertTrue($issuerMetadata->backchannelLogoutSupported());
    }

    public function testBackchannelLogoutSupportedDefault(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertFalse($issuerMetadata->backchannelLogoutSupported());
    }

    public function testBackchannelLogoutSessionSupported(): void
    {
        $metadata = $this->createSampleMetadata();
        $metadata['backchannel_logout_session_supported'] = true;
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertTrue($issuerMetadata->backchannelLogoutSessionSupported());
    }

    public function testBackchannelLogoutSessionSupportedDefault(): void
    {
        $metadata = $this->createSampleMetadata();
        $issuerMetadata = new IssuerMetadata($metadata);

        $this->assertFalse($issuerMetadata->backchannelLogoutSessionSupported());
    }
}
