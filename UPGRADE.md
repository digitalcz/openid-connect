# Upgrade Guide from 0.x to 1.x

> **⚠️ Disclaimer**: This upgrade guide was generated with AI assistance and may contain errors or inaccuracies. Please verify all code examples and procedures against the actual library documentation or source code before using in production.

This guide will help you upgrade your code from version 0.x to 1.x of the OpenID Connect library.

## Overview of Changes

Version 1.x represents a complete architectural overhaul with breaking changes to improve:

- **Factory-based instantiation** - Simplified client creation through `OidcFactory`
- **Facade pattern** - Clean API through the `Oidc` facade with specialized services
- **Modular architecture** - Separate classes for different OAuth2/OIDC flows
- **Enhanced exception hierarchy** - More granular, domain-specific exceptions
- **Resource server support** - Built-in token validation for resource servers
- **Better caching** - HMAC-based secure caching with configurable secrets
- **Symfony contracts** - Uses `symfony/http-client` and `symfony/cache` contracts

## Breaking Changes

### 1. Client Instantiation

**0.x (Old):**
```php
use DigitalCz\OpenIDConnect\ClientFactory;
use DigitalCz\OpenIDConnect\ClientMetadata;

$clientMetadata = new ClientMetadata('clientid', 'clientsecret', 'https://example.com/callback');
$client = ClientFactory::create('https://accounts.google.com', $clientMetadata);
```

**1.x (New):**
```php
use DigitalCz\OpenIDConnect\OidcFactory;
use Symfony\Component\HttpClient\HttpClient;

$httpClient = HttpClient::create();

$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://accounts.google.com',
    clientId: 'clientid',
    clientSecret: 'clientsecret',
    redirectUri: 'https://example.com/callback',
);
```

### 2. Authorization Code Flow

**0.x (Old):**
```php
use DigitalCz\OpenIDConnect\Param\AuthorizationParams;
use DigitalCz\OpenIDConnect\Param\CallbackParams;
use DigitalCz\OpenIDConnect\Param\CallbackChecks;

// Create authorization URL
$authorizationParams = new AuthorizationParams([
    'scope' => 'openid profile',
    'state' => 'foo',
    'nonce' => 'bar',
]);
$url = $client->getAuthorizationUrl($authorizationParams);

// Handle callback
$tokens = $client->handleCallback(
    new CallbackParams($_GET),
    new CallbackChecks($_SESSION['oauth_state'])
);
```

**1.x (New):**
```php
$authorizationCode = $oidc->authorizationCode();

// Create authorization URL
$authorizationUrlResult = $authorizationCode->createAuthorizationUrl([
    'state' => 'foo',
    'nonce' => 'bar'
]);
$url = $authorizationUrlResult->url();
$state = $authorizationUrlResult->state(); // Generated state if not provided
$nonce = $authorizationUrlResult->nonce(); // Generated nonce if not provided

// Handle callback
$code = $_GET['code'];
$tokens = $authorizationCode->fetchTokens($code, 'bar'); // nonce required
```

### 3. Client Credentials Flow

**0.x (Old):**
```php
use DigitalCz\OpenIDConnect\Grant\ClientCredentials;
use DigitalCz\OpenIDConnect\Param\TokenParams;

$tokens = $client->requestTokens(
    new TokenParams(new ClientCredentials(), ['scope' => 'profile'])
);
```

**1.x (New):**
```php
$clientCredentials = $oidc->clientCredentials();
$tokens = $clientCredentials->fetchTokens(['scope' => 'profile']); // optional parameters
```

### 4. Token Access

**0.x (Old):**
```php
// Tokens were accessed directly from the Tokens object
$accessToken = $tokens->getAccessToken();
$idToken = $tokens->getIdToken();
$refreshToken = $tokens->getRefreshToken();
```

**1.x (New):**
```php
// Token classes now have factory methods and better API
$accessToken = $tokens->accessToken();
$idToken = $tokens->idToken(); 
$refreshToken = $tokens->refreshToken();

// Token classes now have dedicated factory methods
use DigitalCz\OpenIDConnect\Client\Tokens;
$tokens = Tokens::fromTokenResponse($responseData); // Create from OAuth response
// or using constructor directly (for specific tokens only):
$tokens = new Tokens(refreshToken: new RefreshToken($refreshToken));
```

### 5. Manual Configuration

**0.x (Old):**
```php
use DigitalCz\OpenIDConnect\Client;
use DigitalCz\OpenIDConnect\Config;
use DigitalCz\OpenIDConnect\ProviderMetadata;

$providerMetadata = new ProviderMetadata([
    ProviderMetadata::AUTHORIZATION_ENDPOINT => 'https://example.com/authorize',
    ProviderMetadata::TOKEN_ENDPOINT => 'https://example.com/token',
]);
$config = new Config($providerMetadata, $clientMetadata);
$client = new Client($config, $httpClient);
```

**1.x (New):**
```php
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;

$issuerMetadata = new IssuerMetadata([
    'authorization_endpoint' => 'https://example.com/authorize',
    'token_endpoint' => 'https://example.com/token',
    'jwks_uri' => 'https://example.com/.well-known/jwks.json',
    'issuer' => 'https://example.com',
]);

$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: $issuerMetadata, // Pass IssuerMetadata directly
    clientId: 'clientid',
    clientSecret: 'clientsecret',
    redirectUri: 'https://example.com/callback',
);
```

### 6. Exception Hierarchy

**0.x (Old):**
- `AuthorizationException`
- `DiscoveryException` 
- `HttpException`
- `MissingParamException`
- `RuntimeException`

**1.x (New):**
- `Exception` (base interface)
- `ConfigurationException`
- `DiscoveryException`
- `IntrospectionException`
- `InvalidTokenException`
- `NetworkException`

**Migration:**
```php
// 0.x
try {
    // OIDC operations
} catch (\DigitalCz\OpenIDConnect\Exception\AuthorizationException $e) {
    // Handle authorization errors
} catch (\DigitalCz\OpenIDConnect\Exception\HttpException $e) {
    // Handle HTTP errors
}

// 1.x
try {
    $authorizationCode = $oidc->authorizationCode();
    $authUrlResult = $authorizationCode->createAuthorizationUrl(['scope' => 'openid profile']);
    $tokens = $authorizationCode->fetchTokens($_GET['code'], $nonce);
    
    $resourceServer = $oidc->resourceServer();
    $validatedToken = $resourceServer->introspect($tokens->accessToken());
    
} catch (\DigitalCz\OpenIDConnect\Exception\InvalidTokenException $e) {
    // Handle token validation errors (invalid JWT, expired token, etc.)
    error_log('Token validation failed: ' . $e->getMessage());
} catch (\DigitalCz\OpenIDConnect\Exception\NetworkException $e) {
    // Handle network/HTTP errors (connection timeout, 5xx responses)
    error_log('Network error: ' . $e->getMessage());
} catch (\DigitalCz\OpenIDConnect\Exception\ConfigurationException $e) {
    // Handle configuration errors (missing endpoints, invalid client config)
    error_log('Configuration error: ' . $e->getMessage());
} catch (\DigitalCz\OpenIDConnect\Exception\DiscoveryException $e) {
    // Handle OIDC discovery errors (invalid discovery document)
    error_log('Discovery error: ' . $e->getMessage());
}
```

## New Features in 1.x

### 1. Resource Server Support

**New in 1.x:**
```php
$resourceServer = $oidc->resourceServer();

// Validate JWT access tokens
use DigitalCz\OpenIDConnect\ResourceServer\JwtAccessToken;
$accessToken = new JwtAccessToken($jwtString);
$validatedToken = $resourceServer->introspect($accessToken);

// Validate opaque tokens via introspection
use DigitalCz\OpenIDConnect\ResourceServer\OpaqueAccessToken;
$accessToken = new OpaqueAccessToken($tokenString);
$validatedToken = $resourceServer->introspect($accessToken);

// Access validated token data
echo $validatedToken->sub(); // Subject
echo $validatedToken->exp(); // Expiration time
echo $validatedToken->scope(); // Scopes
```

### 2. Enhanced Caching with Security

**New in 1.x:**
```php
use Symfony\Component\Cache\Adapter\RedisAdapter;

$cache = new RedisAdapter(/* redis connection */);

$oidc = OidcFactory::create(
    httpClient: $httpClient,
    issuer: 'https://auth.example.com',
    clientId: 'clientid',
    clientSecret: 'clientsecret',
    cache: $cache, // Enable caching
    cacheSecret: 'your-secret-key', // HMAC-based cache keys for security
);
```

### 3. Logout URL Generation

**New in 1.x:**
```php
$authorizationCode = $oidc->authorizationCode();

$logoutUrl = $authorizationCode->createLogoutUrl([
    'post_logout_redirect_uri' => 'https://myapp.example.com/logout-complete',
    'id_token_hint' => $tokens->idToken(),
]);
```

### 4. User Info Endpoint

**New in 1.x:**
```php
$authorizationCode = $oidc->authorizationCode();
$tokens = $authorizationCode->fetchTokens($code, $nonce);

$userinfo = $authorizationCode->fetchUserinfo($tokens);
echo $userinfo->sub(); // Subject
echo $userinfo->get('name'); // Name claim
echo $userinfo->get('email'); // Email claim
```

### 5. Refresh Token Support

**New in 1.x:**
```php
$authorizationCode = $oidc->authorizationCode();

if ($tokens->refreshToken()) {
    $newTokens = $authorizationCode->refreshToken($tokens);
}
```

## Migration Checklist

- [ ] **Update dependencies**: Ensure you have `symfony/http-client` available
- [ ] **Replace ClientFactory**: Use `OidcFactory::create()` instead of `ClientFactory::create()`
- [ ] **Update client instantiation**: Pass HttpClient explicitly and use named parameters
- [ ] **Replace parameter objects**: Remove `AuthorizationParams`, `CallbackParams`, etc. - use arrays instead
- [ ] **Update authorization flow**: Use `$oidc->authorizationCode()->createAuthorizationUrl()` and `fetchTokens()`
- [ ] **Update client credentials**: Use `$oidc->clientCredentials()->fetchTokens()`
- [ ] **Update token access**: Use method calls instead of getters (`accessToken()` not `getAccessToken()`)
- [ ] **Update exception handling**: Catch new exception types
- [ ] **Consider resource server**: Add token validation if building APIs
- [ ] **Add caching**: Consider enabling caching for better performance
- [ ] **Test thoroughly**: The new architecture may reveal edge cases

## Removed Features

### Removed Classes/Interfaces
- `Client` - Replaced by `Oidc` facade with specialized services
- `ClientFactory` - Replaced by `OidcFactory`  
- `ClientMetadata` (old) - Configuration now handled by `OidcFactory` parameters
- `Config` - Replaced by `DiscoveryConfig` and `StaticConfig`
- `ProviderMetadata` - Replaced by `IssuerMetadata`
- All `Param/*` classes - Replaced by simple arrays
- All `Grant/*` classes - Handled internally by specialized client services
- `Token/TokenVerifier*` classes - Replaced by specialized validators

### Removed Methods
- `Client::getAuthorizationUrl()` - Use `AuthorizationCode::createAuthorizationUrl()`
- `Client::handleCallback()` - Use `AuthorizationCode::fetchTokens()`
- `Client::requestTokens()` - Use `ClientCredentials::fetchTokens()`

## Architecture Changes

### 0.x Architecture
```
ClientFactory → Client (monolithic)
├── AuthorizationParams/CallbackParams (parameter objects)
├── Grant types (AuthorizationCode, ClientCredentials)
└── Token verification
```

### 1.x Architecture  
```
OidcFactory → Oidc (facade)
├── AuthorizationCode (specialized service)
├── ClientCredentials (specialized service)  
└── ResourceServer (specialized service)
    ├── JwtAccessTokenValidator
    └── OpaqueAccessTokenValidator
```

The new architecture follows the **Factory → Facade → Specialized Services** pattern, providing:
- Better separation of concerns
- More testable code
- Cleaner APIs
- Enhanced functionality per flow type

## Need Help?

If you encounter issues during migration:

1. Check the [examples](examples/) directory for working code samples
2. Review the [README.md](README.md) for updated usage patterns
3. Look at the test files for advanced usage examples
4. The new architecture is more explicit - most issues stem from trying to use old parameter objects

The 1.x version provides a much more robust and maintainable foundation for OpenID Connect integration.