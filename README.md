# OIDC Discovery

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

```php
$discoveryUri = 'https://example.com/.well-known/openid-configuration';
$clientMetadata = new ClientMetadata('clientid', 'clientsecret', 'https://example.com/callback');
$client = ClientFactory::create($discoveryUri, $clientMetadata);

$authorizationParams = new AuthorizationParams([
    'scope' => 'openid profile',
    'state' => 'foo',
    'nonce' => 'bar',
]);

echo $client->getAuthorizationUrl($authorizationParams); 
// https://example.com/authorize?
//      scope=openid%20profile
//      &state=foo
//      &nonce=bar
//      &response_type=code
//      &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback
//      &client_id=clientid
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
