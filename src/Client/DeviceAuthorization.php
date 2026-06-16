<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use Closure;
use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Exception\DeviceAuthorizationDeniedException;
use DigitalCz\OpenIDConnect\Exception\DeviceAuthorizationException;
use DigitalCz\OpenIDConnect\Exception\DeviceAuthorizationExpiredException;
use DigitalCz\OpenIDConnect\Exception\DeviceAuthorizationPendingException;
use DigitalCz\OpenIDConnect\Exception\SlowDownException;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * OAuth2 Device Authorization Grant (RFC 8628) for browserless and input-constrained devices.
 */
final readonly class DeviceAuthorization
{
    /** Default polling interval when the authorization server omits one (RFC 8628 § 3.5). */
    private const int DEFAULT_POLL_INTERVAL = 5;

    /** Additional seconds added to the polling interval on each "slow_down" error. */
    private const int SLOW_DOWN_INCREMENT = 5;

    /** @var Closure(int): void */
    private Closure $sleeper;

    /**
     * @param (Closure(int): void)|null $sleeper Custom sleeper used by pollForTokens(); defaults to \sleep().
     */
    public function __construct(
        private Config $config,
        private HttpClientInterface $httpClient,
        private ClockInterface $clock = new SimpleClock(),
        ?Closure $sleeper = null,
    ) {
        $this->sleeper = $sleeper ?? static function (int $seconds): void {
            if ($seconds > 0) {
                sleep($seconds);
            }
        };
    }

    /**
     * Request a device and user code from the authorization server.
     *
     * @param array<string, string> $params Additional body parameters (e.g. audience)
     */
    public function requestDeviceAuthorization(array $params = []): DeviceAuthorizationResponse
    {
        $issuerMetadata = $this->config->issuerMetadata();
        $clientMetadata = $this->config->clientMetadata();

        $params['scope'] ??= implode(' ', $clientMetadata->defaultScopes());

        $url = $issuerMetadata->deviceAuthorizationEndpoint();
        $options = ['body' => array_filter($params)];

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $options = $authenticator->applyAuthentication($options);

        /** @var array<string, mixed> $data */
        $data = $this->httpClient->request('POST', $url, $options)->toArray();

        return DeviceAuthorizationResponse::fromResponse($data);
    }

    /**
     * Single attempt to exchange a device code for tokens.
     *
     * Throws a typed exception for each RFC 8628 error code so callers can drive
     * their own polling loop. Use {@see pollForTokens()} for a convenience loop.
     *
     * @param array<string, string> $params Additional body parameters
     *
     * @throws DeviceAuthorizationDeniedException   User denied the request.
     * @throws DeviceAuthorizationException         Any other OAuth error.
     * @throws DeviceAuthorizationExpiredException  Device code expired.
     * @throws DeviceAuthorizationPendingException  User has not yet authorized.
     * @throws SlowDownException                    Polling too fast - increase interval.
     */
    public function fetchTokens(string $deviceCode, array $params = []): Tokens
    {
        $issuerMetadata = $this->config->issuerMetadata();
        $clientMetadata = $this->config->clientMetadata();

        $params['grant_type'] ??= 'urn:ietf:params:oauth:grant-type:device_code';
        $params['device_code'] ??= $deviceCode;

        $url = $issuerMetadata->tokenEndpoint();
        $options = ['body' => array_filter($params)];

        $authenticator = new ClientAuthenticator($clientMetadata, $issuerMetadata);
        $options = $authenticator->applyAuthentication($options);

        $response = $this->httpClient->request('POST', $url, $options);

        /** @var array<string, mixed> $data */
        $data = $response->toArray(false);

        if (isset($data['error']) && is_string($data['error'])) {
            throw $this->mapError($data['error'], $data);
        }

        return Tokens::fromTokenResponse($data);
    }

    /**
     * Poll the token endpoint until authorization completes or fails.
     *
     * Respects the interval from {@see DeviceAuthorizationResponse::interval()} (defaulting
     * to 5 seconds per RFC 8628 § 3.5) and increases it by 5 seconds on every "slow_down"
     * response. Polling stops when a terminal state is reached (tokens returned, expired,
     * denied, or any other non-recoverable error), or when the device code's lifetime
     * elapses.
     *
     * @param array<string, string> $params Additional body parameters forwarded to each poll
     */
    public function pollForTokens(DeviceAuthorizationResponse $response, array $params = []): Tokens
    {
        $interval = $response->interval() ?? self::DEFAULT_POLL_INTERVAL;
        $deadline = $this->clock->now()->getTimestamp() + $response->expiresIn();

        while (true) {
            try {
                return $this->fetchTokens($response->deviceCode(), $params);
            } catch (DeviceAuthorizationPendingException | SlowDownException $e) {
                if ($e instanceof SlowDownException) {
                    $interval += self::SLOW_DOWN_INCREMENT;
                }
            }

            if ($this->clock->now()->getTimestamp() + $interval > $deadline) {
                throw new DeviceAuthorizationExpiredException(
                    'Device code expired before the user completed authorization.',
                    error: 'expired_token',
                );
            }

            ($this->sleeper)($interval);
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    private function mapError(string $error, array $data): DeviceAuthorizationException
    {
        $description = isset($data['error_description']) && is_string($data['error_description'])
            ? $data['error_description']
            : null;

        $message = $description ?? sprintf('Device authorization failed: %s', $error);

        return match ($error) {
            'authorization_pending' => new DeviceAuthorizationPendingException($message, $error, $description),
            'slow_down' => new SlowDownException($message, $error, $description),
            'expired_token' => new DeviceAuthorizationExpiredException($message, $error, $description),
            'access_denied' => new DeviceAuthorizationDeniedException($message, $error, $description),
            default => new DeviceAuthorizationException($message, $error, $description),
        };
    }
}
