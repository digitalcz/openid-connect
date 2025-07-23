# OIDC Connect

[![Latest Stable Version](http://poser.pugx.org/digitalcz/openid-connect/v)](https://packagist.org/packages/digitalcz/openid-connect) 
[![Total Downloads](http://poser.pugx.org/digitalcz/openid-connect/downloads)](https://packagist.org/packages/digitalcz/openid-connect) 
[![Latest Unstable Version](http://poser.pugx.org/digitalcz/openid-connect/v/unstable)](https://packagist.org/packages/digitalcz/openid-connect) 
[![License](http://poser.pugx.org/digitalcz/openid-connect/license)](https://packagist.org/packages/digitalcz/openid-connect) 
[![PHP Version Require](http://poser.pugx.org/digitalcz/openid-connect/require/php)](https://packagist.org/packages/digitalcz/openid-connect)
[![CI](https://github.com/digitalcz/openid-connect/workflows/CI/badge.svg)](https://github.com/digitalcz/openid-connect/actions)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/digitalcz/openid-connect/badges/quality-score.png?b=0.x)](https://scrutinizer-ci.com/g/digitalcz/openid-connect/?branch=0.x)
[![codecov](https://codecov.io/gh/digitalcz/openid-connect/branch/0.x/graph/badge.svg?token=QzZ5iMNkg3)](https://codecov.io/gh/digitalcz/openid-connect)

PHP implementation of https://openid.net/specs/openid-connect-core-1_0.html

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
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use Symfony\Component\HttpClient\HttpClient;

$httpClient = HttpClient::create();
$factory = new OidcFactory($httpClient);

$clientMetadata = new ClientMetadata(
    clientId: 'clientid',
    clientSecret: 'clientsecret',
    redirectUri: 'https://example.com/callback'
);

$oidc = $factory->create('https://example.com', $clientMetadata);
```

<details>
<summary>Using manual configuration</summary>

```php
use DigitalCz\OpenIDConnect\OidcFactory;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use Symfony\Component\HttpClient\HttpClient;

$httpClient = HttpClient::create();
$factory = new OidcFactory($httpClient);

$clientMetadata = new ClientMetadata(
    clientId: 'clientid',
    clientSecret: 'clientsecret',
    redirectUri: 'https://example.com/callback'
);

$issuerMetadata = new IssuerMetadata([
    'authorization_endpoint' => 'https://example.com/authorize',
    'token_endpoint' => 'https://example.com/token',
    'jwks_uri' => 'https://example.com/.well-known/jwks.json',
    'issuer' => 'https://example.com',
]);

$oidc = $factory->create($issuerMetadata, $clientMetadata);
```
</details>

### Authorization Code flow

#### Step 1 - Redirect the user to authorization endpoint

```php
$authorizationCode = $oidc->authorizationCode();

$url = $authorizationCode->createAuthorizationUrl([
    'state' => 'random-state',
    'nonce' => 'random-nonce'
]);

// Redirect user to $url
```

#### Step 2 - Handle the callback and exchange code for tokens

```php
// Get the authorization code from the callback URL
$code = $_GET['code'];
$nonce = 'random-nonce'; // Same nonce used in step 1

$tokens = $authorizationCode->fetchTokens($code, $nonce);

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
$resourceServer = $oidc->resourceServer();

// Validate an access token
$accessToken = $resourceServer->validateAccessToken($tokenString);

echo "Token is valid for client: " . $accessToken->clientId() . PHP_EOL;
echo "Token expires at: " . $accessToken->expiresAt()->format('Y-m-d H:i:s') . PHP_EOL;
```

See [examples](examples) for more complete examples

## Change log

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

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
