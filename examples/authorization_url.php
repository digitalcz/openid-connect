<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\ClientMetadata;
use DigitalCz\OpenIDConnect\Factory\ClientFactory;
use DigitalCz\OpenIDConnect\Param\AuthorizationParams;

require dirname(__DIR__) . '/vendor/autoload.php';

$discoveryUri = 'https://accounts.google.com/.well-known/openid-configuration';
$clientMetadata = new ClientMetadata('clientid', 'clientsecret', 'https://example.com/callback');
$client = ClientFactory::create($discoveryUri, $clientMetadata);

echo $client->getAuthorizationUrl(
    new AuthorizationParams([
        'scope' => 'openid profile.email',
        'state' => 'foo',
        'nonce' => 'bar',
    ])
);
