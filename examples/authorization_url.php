<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\ClientMetadata;
use DigitalCz\OpenIDConnect\Factory\ClientFactory;
use DigitalCz\OpenIDConnect\Param\AuthorizationParams;

require dirname(__DIR__) . '/vendor/autoload.php';

$clientMetadata = new ClientMetadata('clientid', 'clientsecret', 'https://example.com/callback');
$client = ClientFactory::create('https://accounts.google.com', $clientMetadata);

echo $client->getAuthorizationUrl(
    new AuthorizationParams([
        'scope' => 'openid profile',
        'state' => 'foo',
        'nonce' => 'bar',
    ])
);
