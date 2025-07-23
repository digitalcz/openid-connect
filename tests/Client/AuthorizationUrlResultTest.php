<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(AuthorizationUrlResult::class)]
class AuthorizationUrlResultTest extends TestCase
{
    public function testConstructorWithMinimalParameters(): void
    {
        $url = 'https://auth.example.com/oauth/authorize?client_id=test&redirect_uri=callback';
        $state = 'random-state-value';

        $result = new AuthorizationUrlResult($url, $state);

        $this->assertSame($url, $result->url());
        $this->assertSame($state, $result->state());
        $this->assertNull($result->nonce());
        $this->assertNull($result->codeVerifier());
        $this->assertSame($url, (string) $result);
    }

    public function testConstructorWithAllParameters(): void
    {
        $url = 'https://auth.example.com/oauth/authorize?client_id=test&scope=openid+profile';
        $state = 'csrf-protection-state';
        $nonce = 'id-token-nonce';
        $codeVerifier = 'pkce-code-verifier-value';

        $result = new AuthorizationUrlResult($url, $state, $nonce, $codeVerifier);

        $this->assertSame($url, $result->url());
        $this->assertSame($state, $result->state());
        $this->assertSame($nonce, $result->nonce());
        $this->assertSame($codeVerifier, $result->codeVerifier());
        $this->assertSame($url, (string) $result);
    }

    public function testWithNonceButNoCodeVerifier(): void
    {
        $url = 'https://auth.example.com/oauth/authorize?client_id=test&scope=openid';
        $state = 'state-value';
        $nonce = 'nonce-for-openid';

        $result = new AuthorizationUrlResult($url, $state, $nonce);

        $this->assertSame($url, $result->url());
        $this->assertSame($state, $result->state());
        $this->assertSame($nonce, $result->nonce());
        $this->assertNull($result->codeVerifier());
    }

    public function testWithCodeVerifierButNoNonce(): void
    {
        $url = 'https://auth.example.com/oauth/authorize?client_id=test&scope=read+write';
        $state = 'state-value';
        $codeVerifier = 'pkce-verifier';

        $result = new AuthorizationUrlResult($url, $state, null, $codeVerifier);

        $this->assertSame($url, $result->url());
        $this->assertSame($state, $result->state());
        $this->assertNull($result->nonce());
        $this->assertSame($codeVerifier, $result->codeVerifier());
    }

    public function testToStringReturnsUrl(): void
    {
        $url = 'https://auth.example.com/oauth/authorize?complex=params&state=embedded';
        $state = 'test-state';

        $result = new AuthorizationUrlResult($url, $state);

        $this->assertSame($url, $result->__toString());
        $this->assertSame($url, (string) $result);
    }

    public function testUrlWithComplexQueryParameters(): void
    {
        $url = 'https://auth.example.com/oauth/authorize?' .
               'client_id=test-client-123&' .
               'redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&' .
               'scope=openid+profile+email+custom%3Aread&' .
               'response_type=code&' .
               'state=complex-state-with-encoded-chars%20%21%40%23&' .
               'nonce=nonce-value&' .
               'code_challenge=challenge&' .
               'code_challenge_method=S256';

        $state = 'complex-state-with-encoded-chars !@#';
        $nonce = 'nonce-value';
        $codeVerifier = 'complex-code-verifier-with-symbols_.-~';

        $result = new AuthorizationUrlResult($url, $state, $nonce, $codeVerifier);

        $this->assertStringContainsString('client_id=test-client-123', $result->url());
        $this->assertStringContainsString('scope=openid+profile+email+custom%3Aread', $result->url());
        $this->assertStringContainsString('code_challenge=challenge', $result->url());
        $this->assertSame($state, $result->state());
        $this->assertSame($nonce, $result->nonce());
        $this->assertSame($codeVerifier, $result->codeVerifier());
    }

    public function testEmptyStringValues(): void
    {
        $url = 'https://auth.example.com/oauth/authorize';
        $state = '';
        $nonce = '';
        $codeVerifier = '';

        $result = new AuthorizationUrlResult($url, $state, $nonce, $codeVerifier);

        $this->assertSame($url, $result->url());
        $this->assertSame('', $result->state());
        $this->assertSame('', $result->nonce());
        $this->assertSame('', $result->codeVerifier());
    }

    public function testWithRealWorldExample(): void
    {
        // Example from a real OIDC authorization request
        $url = 'https://accounts.google.com/oauth/v2/auth?' .
               'client_id=123456789.apps.googleusercontent.com&' .
               'redirect_uri=https%3A%2F%2Fmyapp.example.com%2Fauth%2Fcallback&' .
               'scope=openid+profile+email&' .
               'response_type=code&' .
               'state=xyz123abc&' .
               'nonce=abc456def&' .
               'code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&' .
               'code_challenge_method=S256';

        $state = 'xyz123abc';
        $nonce = 'abc456def';
        $codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

        $result = new AuthorizationUrlResult($url, $state, $nonce, $codeVerifier);

        $this->assertStringStartsWith('https://accounts.google.com', $result->url());
        $this->assertStringContainsString('openid+profile+email', $result->url());
        $this->assertStringContainsString('code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', $result->url());
        $this->assertSame('xyz123abc', $result->state());
        $this->assertSame('abc456def', $result->nonce());
        $this->assertSame('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', $result->codeVerifier());
    }

    public function testSecurityParametersScenarios(): void
    {
        // Scenario 1: Public client with PKCE and OpenID (full security)
        $fullSecurityResult = new AuthorizationUrlResult(
            'https://auth.example.com/oauth/authorize?full_security=true',
            'csrf-state',
            'id-token-nonce',
            'pkce-verifier',
        );

        $this->assertNotNull($fullSecurityResult->state());
        $this->assertNotNull($fullSecurityResult->nonce());
        $this->assertNotNull($fullSecurityResult->codeVerifier());

        // Scenario 2: Confidential client with OpenID (nonce only)
        $nonceOnlyResult = new AuthorizationUrlResult(
            'https://auth.example.com/oauth/authorize?confidential=true',
            'csrf-state',
            'id-token-nonce',
        );

        $this->assertNotNull($nonceOnlyResult->state());
        $this->assertNotNull($nonceOnlyResult->nonce());
        $this->assertNull($nonceOnlyResult->codeVerifier());

        // Scenario 3: OAuth2 only (no OpenID, state only)
        $stateOnlyResult = new AuthorizationUrlResult(
            'https://auth.example.com/oauth/authorize?oauth2_only=true',
            'csrf-state',
        );

        $this->assertNotNull($stateOnlyResult->state());
        $this->assertNull($stateOnlyResult->nonce());
        $this->assertNull($stateOnlyResult->codeVerifier());
    }

    public function testLongValues(): void
    {
        $longUrl = 'https://auth.example.com/oauth/authorize?' . str_repeat('param=value&', 100);
        $longState = str_repeat('state-part-', 50);
        $longNonce = str_repeat('nonce-part-', 50);
        $longCodeVerifier = str_repeat('verifier-part-', 50);

        $result = new AuthorizationUrlResult($longUrl, $longState, $longNonce, $longCodeVerifier);

        $this->assertSame($longUrl, $result->url());
        $this->assertSame($longState, $result->state());
        $this->assertSame($longNonce, $result->nonce());
        $this->assertSame($longCodeVerifier, $result->codeVerifier());
        $this->assertSame($longUrl, (string) $result);
    }

    public function testReadonlyProperties(): void
    {
        $url = 'https://auth.example.com/oauth/authorize';
        $state = 'test-state';
        $nonce = 'test-nonce';
        $codeVerifier = 'test-verifier';

        $result = new AuthorizationUrlResult($url, $state, $nonce, $codeVerifier);

        // Verify that all properties return the same values consistently
        $this->assertSame($url, $result->url());
        $this->assertSame($url, $result->url()); // Second call should return same value

        $this->assertSame($state, $result->state());
        $this->assertSame($state, $result->state()); // Second call should return same value

        $this->assertSame($nonce, $result->nonce());
        $this->assertSame($nonce, $result->nonce()); // Second call should return same value

        $this->assertSame($codeVerifier, $result->codeVerifier());
        $this->assertSame($codeVerifier, $result->codeVerifier()); // Second call should return same value
    }
}
