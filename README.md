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
use DigitalCz\OpenIDConnect\ClientMetadata;
use DigitalCz\OpenIDConnect\ClientFactory;

$issuerUrl = 'https://example.com';
$clientMetadata = new ClientMetadata('clientid', 'clientsecret', 'https://example.com/callback');
$client = ClientFactory::create($issuerUrl, $clientMetadata);
```

<details>
<summary>Manually</summary>

```php
use DigitalCz\OpenIDConnect\Client;
use DigitalCz\OpenIDConnect\ClientMetadata;
use DigitalCz\OpenIDConnect\Config;
use DigitalCz\OpenIDConnect\Http\HttpClientFactory;
use DigitalCz\OpenIDConnect\Token\TokenVerifierFactory;
use DigitalCz\OpenIDConnect\ProviderMetadata;

$clientMetadata = new ClientMetadata('clientid', 'clientsecret', 'https://example.com/callback');
$providerMetadata = new ProviderMetadata([
    ProviderMetadata::AUTHORIZATION_ENDPOINT => 'https://example.com/authorize',
    ProviderMetadata::TOKEN_ENDPOINT => 'https://example.com/token',
    // ...
])
$config = new Config($providerMetadata, $clientMetadata);
$client = new Client($config, HttpClientFactory::create());
```
</details>

### Authorization Code flow

#### Step 1 - Redirect the user to authorization endpoint

```php
use DigitalCz\OpenIDConnect\Param\AuthorizationParams;

$state = bin2hex(random_bytes(8));
$_SESSION['oauth_state'] = $state;

$authorizationParams = new AuthorizationParams([
    AuthorizationParams::SCOPE => 'openid profile',
    AuthorizationParams::STATE => $state,
]);

$url = $client->getAuthorizationUrl($authorizationParams); 
header('Location: ' . $url);
exit();
```

#### Step 2 - Handle callback and exchange code for tokens

```php
use DigitalCz\OpenIDConnect\Param\CallbackParams;
use DigitalCz\OpenIDConnect\Param\CallbackChecks;

$tokens = $client->handleCallback(
    new CallbackParams($_GET),
    new CallbackChecks($_SESSION['oauth_state'])
);
```

### Client Credentials flow

```php
use DigitalCz\OpenIDConnect\Grant\ClientCredentials;
use DigitalCz\OpenIDConnect\Param\TokenParams;

$tokens = $client->requestTokens(
    new TokenParams(
        new ClientCredentials(),
        [
            TokenParams::SCOPE => 'some scope'
        ]
    )
);
```

See [examples](examples) for more

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
