<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\ClientFactory;
use DigitalCz\OpenIDConnect\ClientMetadata;
use DigitalCz\OpenIDConnect\Param\CallbackChecks;
use DigitalCz\OpenIDConnect\Param\CallbackParams;

require dirname(__DIR__) . '/vendor/autoload.php';

$issuerUrl = 'https://accounts.google.com';
$clientMetadata = new ClientMetadata('clientid', 'clientsecret', 'https://example.com/callback');
$client = ClientFactory::create($issuerUrl, $clientMetadata);

// Parameters that were returned from authorization server
// $parameters = $request->query->all();
$parameters = ['state' => 'foo', 'code' => 'bar'];

$tokens = $client->handleCallback(
    new CallbackParams($parameters),
    new CallbackChecks('foo', 'bar'),
);

dump($tokens);
