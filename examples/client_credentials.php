<?php

declare(strict_types=1);

use DigitalCz\OpenIDConnect\ClientMetadata;
use DigitalCz\OpenIDConnect\Factory\ClientFactory;
use DigitalCz\OpenIDConnect\Grant\ClientCredentials;
use DigitalCz\OpenIDConnect\Param\TokenParams;

require dirname(__DIR__) . '/vendor/autoload.php';

$discoveryUri = 'https://accounts.google.com/.well-known/openid-configuration';
$clientMetadata = new ClientMetadata('clientid', 'clientsecret', 'https://example.com/callback');
$client = ClientFactory::create($discoveryUri, $clientMetadata);

$tokens = $client->requestTokens(new TokenParams(new ClientCredentials(), ['scope' => 'profile']));

dump($tokens);
