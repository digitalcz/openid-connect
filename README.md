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
| `backchannelLogoutUri`        | `string\|null`                  | -        | `null`                           | RP endpoint the OP POSTs logout tokens to (informational; exposed via `clientMetadata()`)                  |
| `backchannelLogoutSessionRequired` | `bool`                     | -        | `false`                          | Require the `sid` claim in logout tokens (rejected without it when `true`)                                 |

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

### Device Authorization flow

Implements the OAuth 2.0 Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) for
browserless and input-constrained devices. Requires the provider to expose a `device_authorization_endpoint`.

#### Step 1 - Request a device and user code

```php
$device = $oidc->deviceAuthorization();

$response = $device->requestDeviceAuthorization();

// Show these to the user, who completes authorization on another device.
echo "Go to: " . $response->verificationUri() . PHP_EOL;
echo "Enter code: " . $response->userCode() . PHP_EOL;

// verificationUriComplete() embeds the code so the user can skip typing it (e.g. as a QR code).
if ($response->verificationUriComplete() !== null) {
    echo "Or open: " . $response->verificationUriComplete() . PHP_EOL;
}
```

#### Step 2 - Poll for tokens

`pollForTokens()` blocks until the user completes (or denies) authorization, honoring the server's polling
`interval` and backing off automatically on `slow_down`:

```php
use DigitalCz\OpenIDConnect\Exception\DeviceAuthorizationDeniedException;
use DigitalCz\OpenIDConnect\Exception\DeviceAuthorizationExpiredException;

try {
    $tokens = $device->pollForTokens($response);
    echo "Access Token: " . $tokens->accessToken() . PHP_EOL;
} catch (DeviceAuthorizationDeniedException $e) {
    echo "User denied the request." . PHP_EOL;
} catch (DeviceAuthorizationExpiredException $e) {
    echo "Device code expired - restart the flow." . PHP_EOL;
}
```

If you need to drive the polling loop yourself, call `fetchTokens()` for a single attempt. It throws a typed
exception per RFC 8628 error code: `DeviceAuthorizationPendingException`, `SlowDownException`,
`DeviceAuthorizationExpiredException`, `DeviceAuthorizationDeniedException`, or the base
`DeviceAuthorizationException` for any other error.

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

#### Audience validation

By default the resource server accepts only tokens whose `aud` claim matches the `clientId`. Use
`resourceServerAudience` to decouple the accepted audience from the client id — for example when the resource
server has several identities of its own, or when it must accept tokens minted for other first-party services:

```php
// Accept a token whose "aud" matches any of the listed audiences.
$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://issuer.example.com',
    clientId: 'my-client',
    resourceServerAudience: ['service-a', 'service-b'],
);

// Disable the audience check entirely (validate signature + issuer + expiry only).
$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://issuer.example.com',
    clientId: 'my-client',
    resourceServerAudience: null,
);
```

Passing a **list** verifies that the token's `aud` (a single value or an array) intersects the configured
audiences — this is the standard model for a resource server with multiple identities (RFC 9068 §4).

Passing **`null`** turns the audience check off. This is a **deliberate deviation from RFC 9068**, which requires
rejecting a token whose `aud` does not identify the resource server. It exists for closed first-party token
propagation across services sharing one issuer; the standards-correct alternative is
[Token Exchange (RFC 8693)](https://www.rfc-editor.org/rfc/rfc8693). The presence of the `aud` claim itself is
still governed by the validator's mandatory-claims set. Leaving `resourceServerAudience` unset keeps the default
(`aud` must equal `clientId`).

When wiring `JwtAccessTokenValidator` manually, the same `string|list<string>|null` values apply to its `$audience`
argument. For fully custom validation you can inject a replacement set of claim checkers via `$claimCheckers`, which
then supersedes the default issuer/audience/expiry/issued-at/not-before checkers.

### Back-Channel Logout

Implements [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html).
The OP sends a server-to-server POST with a `logout_token` to your registered back-channel logout endpoint. Pass that
token to the handler — it verifies the signature against the issuer JWKS and validates the logout-token claims
(`iss`, `aud`, `iat`, `events`, no `nonce`, and `sub` and/or `sid`).

```php
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;

$handler = $oidc->backChannelLogout();

try {
    // $_POST['logout_token'] is the form-encoded parameter sent by the OP
    $logoutToken = $handler->handleLogoutRequest($_POST['logout_token']);
} catch (InvalidTokenException $e) {
    http_response_code(400);
    return;
}

// Terminate the matching session(s). Use sid (this session) and/or sub (all of the user's sessions).
$sid = $logoutToken->sid(); // ?string
$sub = $logoutToken->sub(); // ?string

http_response_code(200);
```

Two responsibilities the spec leaves to the application are intentionally left to you:

- **Replay protection** — verify the `jti` (exposed via `$logoutToken->jti()`) has not been seen recently before
  acting on the token.
- **Session termination** — map `sid`/`sub` to your session store and destroy the relevant session(s).

If the client is registered with `backchannelLogoutSessionRequired: true`, logout tokens without a `sid` claim are
rejected.

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
