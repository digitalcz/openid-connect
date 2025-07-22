<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use Symfony\Contracts\HttpClient\HttpClientInterface;

final readonly class HttpJwksLoader implements JwksLoader
{
    public function __construct(
        private HttpClientInterface $httpClient,
    ) {
    }

    /**
     * @return mixed[]
     */
    public function load(string $jwksUri): array
    {
        return $this->httpClient->request('GET', $jwksUri)->toArray();
    }
}
