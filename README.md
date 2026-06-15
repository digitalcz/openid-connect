# OIDC Connect

[![Latest Stable Version](http://poser.pugx.org/digitalcz/openid-connect/v)](https://packagist.org/packages/digitalcz/openid-connect) 
[![Total Downloads](http://poser.pugx.org/digitalcz/openid-connect/downloads)](https://packagist.org/packages/digitalcz/openid-connect) 
[![Latest Unstable Version](http://poser.pugx.org/digitalcz/openid-connect/v/unstable)](https://packagist.org/packages/digitalcz/openid-connect) 
[![License](http://poser.pugx.org/digitalcz/openid-connect/license)](https://packagist.org/packages/digitalcz/openid-connect) 
[![PHP Version Require](http://poser.pugx.org/digitalcz/openid-connect/require/php)](https://packagist.org/packages/digitalcz/openid-connect)
[![CI](https://github.com/digitalcz/openid-connect/workflows/CI/badge.svg)](https://github.com/digitalcz/openid-connect/actions)
[![codecov](https://codecov.io/gh/digitalcz/openid-connect/branch/1.x/graph/badge.svg?token=QzZ5iMNkg3)](https://codecov.io/gh/digitalcz/openid-connect)

PHP implementation of [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) using symfony/contracts

## Install

Via [Composer](https://getcomposer.org/)

```bash
$ composer require digitalcz/openid-connect
```

## Usage

### Initialization
#### Using the OIDC discovery endpoint

```php
use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

$httpClient = HttpClient::create();

$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://auth.example.com',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
    redirectUri: 'https://myapp.example.com/callback',
);
```

<details>
<summary>Using manual issuer configuration</summary>

```php
use DigitalCz\OpenIDConnect\OidcFactory;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use Symfony\Component\HttpClient\HttpClient;

$httpClient = HttpClient::create();

$issuerMetadata = new IssuerMetadata([
    'authorization_endpoint' => 'https://auth.example.com/authorize',
    'token_endpoint' => 'https://auth.example.com/token',
    'jwks_uri' => 'https://auth.example.com/.well-known/jwks.json',
    'issuer' => 'https://auth.example.com',
]);

$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: $issuerMetadata,
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
    redirectUri: 'https://myapp.example.com/callback',
);
```
</details>

### Configuration Options

The `OidcFactory::create()` method accepts the following configuration options:

| Parameter                     | Type                            | Required | Default                          | Description                                                                                                |
|-------------------------------|---------------------------------|----------|----------------------------------|------------------------------------------------------------------------------------------------------------|
| `httpClient`                  | `HttpClientInterface`           | ✓        | -                                | HTTP client for making requests                                                                            |
| `issuer`                      | `string\|array\|IssuerMetadata` | ✓        | -                                | Issuer URL for discovery, metadata array, or IssuerMetadata instance                                       |
| `clientId`                    | `string`                        | ✓        | -                                | OAuth2/OIDC client identifier                                                                              |
| `clientSecret`                | `string\|null`                  | -        | `null`                           | OAuth2/OIDC client secret (required for some authentication methods)                                       |
| `redirectUri`                 | `string\|null`                  | -        | `null`                           | Redirect URI for authorization code flow                                                                   |
| `defaultScopes`               | `string\|array`                 | -        | `['openid', 'profile', 'email']` | Default scopes to request (space-separated string or array)                                                |
| `authenticationMethod`        | `string\|AuthenticationMethod`  | -        | `client_secret_post`             | Client authentication method for token endpoint                                                            |
| `pkceMethod`                  | `string\|PkceMethod`            | -        | `S256`                           | PKCE method for authorization code flow (`S256`, `plain`, or `none`)                                       |
| `cache`                       | `CacheInterface\|null`          | -        | `null`                           | Optional cache for storing discovery metadata and JWKS                                                     |
| `clock`                       | `ClockInterface`                | -        | `SimpleClock`                    | Clock implementation for time-based operations                                                             |
| `cacheSecret`                 | `string`                        | -        | `'default-oidc-cache-secret'`    | Secret used for HMAC-based cache key generation                                                            |
| `privateKey`                  | `string\|null`                  | -        | `null`                           | PEM-encoded private key for `private_key_jwt` authentication                                               |
| `privateKeyJwk`               | `JWK\|null`                     | -        | `null`                           | JWK private key for `private_key_jwt` authentication (alternative to `privateKey`)                         |
| `tokenEndpointAuthSigningAlg` | `string\|null`                  | -        | `null`                           | Signature algorithm for client assertion JWT (e.g., `'HS256'`, `'RS256'`)                                  |
| `clientAssertionAudience`     | `string\|null`                  | -        | `null`                           | Audience claim for client assertion JWT. Special values: `'{issuer}'`, `'{token_endpoint}'`, or custom URL |
| `accessTokenType`             | `string\|null`                  | -        | `null`                           | Expected JWT access-token `typ` header (RFC 9068, e.g. `'at+jwt'`); `null` disables the check              |

#### Authentication Methods

- `client_secret_post` - Send client credentials in POST body
- `client_secret_basic` - Send client credentials in Authorization header
- `client_secret_jwt` - Use JWT signed with client secret
- `private_key_jwt` - Use JWT signed with private key
- `none` - No client authentication (public clients)

### Authorization Code flow

#### Step 1 - Redirect the user to authorization endpoint

```php
$authorizationCode = $oidc->authorizationCode();

// createAuthorizationUrl() auto-generates cryptographically random state, nonce, and PKCE
// code_verifier. Retrieve them from the result and persist in session before redirecting.
$result = $authorizationCode->createAuthorizationUrl();

// IMPORTANT: Store security parameters in session before redirecting.
// - state: must be verified on callback to prevent CSRF attacks
// - nonce: must be passed to fetchTokens() to validate the ID token
// - codeVerifier: must be passed to fetchTokens() when PKCE is enabled (default)
session_start();
$_SESSION['oauth_state'] = $result->state();
$_SESSION['oauth_nonce'] = $result->nonce();
$_SESSION['oauth_code_verifier'] = $result->codeVerifier();

// Redirect user to $result->url()
```

#### Step 2 - Handle the callback and exchange code for tokens

```php
session_start();

// IMPORTANT: Always validate the state parameter before proceeding.
// A missing or mismatched state indicates a potential CSRF attack.
if (
    empty($_GET['state'])
    || !isset($_SESSION['oauth_state'])
    || !hash_equals($_SESSION['oauth_state'], $_GET['state'])
) {
    throw new RuntimeException('Invalid state parameter - possible CSRF attack.');
}

$code = $_GET['code'];

$tokens = $authorizationCode->fetchTokens(
    code: $code,
    nonce: $_SESSION['oauth_nonce'],
    codeVerifier: $_SESSION['oauth_code_verifier'],
);

// Clear one-time security parameters from session
unset($_SESSION['oauth_state'], $_SESSION['oauth_nonce'], $_SESSION['oauth_code_verifier']);

echo "Access Token: " . $tokens->accessToken() . PHP_EOL;
echo "ID Token: " . $tokens->idToken() . PHP_EOL;
echo "Refresh Token: " . $tokens->refreshToken() . PHP_EOL;
```

### Client Credentials flow

```php
$clientCredentials = $oidc->clientCredentials();
$tokens = $clientCredentials->fetchTokens();

echo "Access Token: " . $tokens->accessToken() . PHP_EOL;
```

### Resource Server (Token Validation)

```php
use DigitalCz\OpenIDConnect\ResourceServer\JwtAccessToken;
use DigitalCz\OpenIDConnect\ResourceServer\OpaqueAccessToken;
use DigitalCz\OpenIDConnect\Util\JWT;

$resourceServer = $oidc->resourceServer();

$accessToken = new JwtAccessToken($jwt);
$validatedToken = $resourceServer->introspect($accessToken);

echo "Token is valid for subject: " . $validatedToken->sub() . PHP_EOL;
echo "Token expires at: " . date('Y-m-d H:i:s', $validatedToken->exp()) . PHP_EOL;
```

To follow [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) and require JWT access tokens to be explicitly typed
(rejecting, for example, an ID token presented as an access token), set `accessTokenType`:

```php
$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://issuer.example.com',
    clientId: 'my-client',
    accessTokenType: 'at+jwt',
);
```

When set, the `typ` header must be present and equal to the expected value; both `at+jwt` and `application/at+jwt`
are accepted. It is disabled by default because not all authorization servers emit the `typ` header.

See [examples](examples) for more complete examples

## Testing

``` bash
$ composer csfix    # fix codestyle
$ composer checks   # run all checks 

# or separately
$ composer tests    # run phpunit
$ composer phpstan  # run phpstan
$ composer cs       # run codesniffer
```

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email devs@digital.cz instead of using the issue tracker.

## Credits

- [Digital Solutions s.r.o.][link-author]
- [All Contributors][link-contributors]

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.

[link-author]: https://github.com/digitalcz
[link-contributors]: ../../contributors
