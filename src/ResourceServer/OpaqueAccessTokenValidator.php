<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * Opaque access token validator
 */
final readonly class OpaqueAccessTokenValidator implements AccessTokenValidator
{
    public function __construct(
        private Config $config,
        private HttpClientInterface $httpClient,
    ) {
    }

    /**
     * Support opaque tokens only
     */
    public function supports(AccessToken $token): bool
    {
        return $token instanceof OpaqueAccessToken;
    }

    /**
     * Validate via introspection endpoint
     */
    public function validate(AccessToken $token): ValidatedAccessToken
    {
        if (!$token instanceof OpaqueAccessToken) {
            throw new InvalidTokenException('Token is not an opaque token');
        }

        $issuerMetadata = $this->config->issuerMetadata();
        $introspectionEndpoint = $issuerMetadata->introspectionEndpoint();
        $clientMetadata = $this->config->clientMetadata();

        try {
            $options = ['body' => ['token' => (string) $token]];
            $options = $clientMetadata->applyCredentials($options);

            /** @var array<string, mixed> $claims */
            $claims = $this->httpClient->request('POST', $introspectionEndpoint, $options)->toArray();

            if (!isset($claims['active']) || $claims['active'] !== true) {
                throw new InvalidTokenException('Token is not active');
            }

            return new ValidatedAccessToken($token, $claims);
        } catch (Throwable $e) {
            throw new InvalidTokenException('Token introspection failed: ' . $e->getMessage(), 0, $e);
        }
    }
}
