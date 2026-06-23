<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\HttpClient\ResponseStreamInterface;

/**
 * HttpClient decorator enforcing transport security (HTTPS) on every outbound request URL.
 *
 * Acts as a single choke point so discovery, JWKS, token, userinfo and introspection
 * requests are all guarded, including any request site added later.
 */
final class SecureHttpClient implements HttpClientInterface
{
    public function __construct(
        private readonly HttpClientInterface $httpClient,
    ) {
    }

    /**
     * @param array<string, mixed> $options
     *
     * @throws DiscoveryException if the URL is not transport-secure (non-HTTPS, non-loopback)
     * @throws TransportExceptionInterface when an unsupported option is passed
     */
    public function request(string $method, string $url, array $options = []): ResponseInterface
    {
        SecureUrl::requireSecure($url);

        return $this->httpClient->request($method, $url, $options);
    }

    /**
     * @param ResponseInterface|iterable<int|string, ResponseInterface> $responses
     */
    public function stream(ResponseInterface|iterable $responses, ?float $timeout = null): ResponseStreamInterface
    {
        return $this->httpClient->stream($responses, $timeout);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function withOptions(array $options): static
    {
        return new self($this->httpClient->withOptions($options));
    }
}
