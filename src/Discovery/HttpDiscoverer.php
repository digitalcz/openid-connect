<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Discovery;

use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\DecodingExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * HTTP-based OIDC discovery.
 */
final class HttpDiscoverer implements Discoverer
{
    public function __construct(
        private readonly HttpClientInterface $httpClient,
    ) {
    }

    /**
     * @throws DiscoveryException
     * @throws NetworkException
     */
    public function discover(string $issuer): IssuerMetadata
    {
        $discoveryUrl = rtrim($issuer, '/') . '/.well-known/openid-configuration';

        try {
            /** @var array<string, string|string[]|bool> $response */
            $response = $this->httpClient->request('GET', $discoveryUrl)->toArray();
        } catch (TransportExceptionInterface $e) {
            throw new NetworkException('Failed to fetch OIDC discovery document: ' . $e->getMessage(), 0, $e);
        } catch (ClientExceptionInterface | RedirectionExceptionInterface | ServerExceptionInterface $e) {
            throw new DiscoveryException('OIDC discovery endpoint returned error: ' . $e->getMessage(), 0, $e);
        } catch (DecodingExceptionInterface $e) {
            throw new DiscoveryException('Failed to decode OIDC discovery document: ' . $e->getMessage(), 0, $e);
        } catch (Throwable $e) {
            throw new DiscoveryException('Unexpected error during OIDC discovery: ' . $e->getMessage(), 0, $e);
        }

        $this->assertIssuerMatches($issuer, $response);

        return new IssuerMetadata($response);
    }

    /**
     * Verifies the discovery document's issuer matches the configured issuer (OIDC Discovery 1.0 §4.3).
     *
     * @param array<string, string|string[]|bool> $response
     *
     * @throws DiscoveryException
     */
    private function assertIssuerMatches(string $issuer, array $response): void
    {
        $returnedIssuer = $response['issuer'] ?? null;

        if (!is_string($returnedIssuer) || rtrim($returnedIssuer, '/') !== rtrim($issuer, '/')) {
            throw new DiscoveryException(sprintf(
                'OIDC discovery issuer mismatch: expected "%s", got "%s".',
                $issuer,
                is_string($returnedIssuer) ? $returnedIssuer : '(missing)',
            ));
        }
    }
}
