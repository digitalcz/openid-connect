<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\ClientMetadata;
use DigitalCz\OpenIDConnect\Factory\ClientFactory;
use DigitalCz\OpenIDConnect\Param\CallbackChecks;
use DigitalCz\OpenIDConnect\Param\CallbackParams;

require dirname(__DIR__) . '/vendor/autoload.php';

$discoveryUri = 'https://accounts.google.com/.well-known/openid-configuration';
$clientMetadata = new ClientMetadata('clientid', 'clientsecret', 'https://example.com/callback');
$client = ClientFactory::create($discoveryUri, $clientMetadata);

// Parameters that were returned from authorization server
// $parameters = $_GET;
$parameters = ['state' => 'foo', 'code' => 'bar'];

$tokens = $client->handleCallback(
    new CallbackParams($parameters),
    new CallbackChecks('foo', 'bar')
);

dump($tokens);
