<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\Exception\InvalidLogoutTokenException;
use DigitalCz\OpenIDConnect\Exception\LogoutTokenExpiredException;
use DigitalCz\OpenIDConnect\Exception\UntrustedLogoutTokenException;
use DigitalCz\OpenIDConnect\Util\SignatureAlgorithmsFactory;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * Validates Back-Channel Logout tokens according to the OIDC Back-Channel Logout specification.
 */
final class LogoutTokenValidator
{
    private const LOGOUT_EVENT_URI = 'http://schemas.openid.net/event/backchannel-logout';

    private ?ClaimCheckerManager $claimCheckerManager = null;
    private ?JWSLoader $jwsLoader = null;

    /**
     * @param list<string> $mandatoryClaims
     */
    public function __construct(
        private readonly Config $config,
        private readonly JwksLoader $jwksLoader,
        private readonly ClockInterface $clock = new SimpleClock(),
        private readonly int $allowedTimeDrift = 10, // seconds
        private readonly array $mandatoryClaims = ['iss', 'aud', 'iat', 'jti', 'events'],
    ) {
    }

    /**
     * Validates a logout token.
     *
     * @throws InvalidLogoutTokenException If the token is malformed or invalid
     * @throws LogoutTokenExpiredException If the token has expired
     * @throws UntrustedLogoutTokenException If the token signature is invalid
     */
    public function validate(string $logoutToken): LogoutToken
    {
        try {
            $token = LogoutToken::from($logoutToken);

            $this->validateSignature($token);
            $this->validateClaims($token);
            $this->validateLogoutSpecificClaims($token);

            return $token;
        } catch (LogoutTokenExpiredException | UntrustedLogoutTokenException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidLogoutTokenException('Invalid Logout Token: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Validates token signature using JWKS.
     *
     * @throws UntrustedLogoutTokenException
     */
    private function validateSignature(LogoutToken $token): void
    {
        try {
            $jwksUri = $this->config->issuerMetadata()->jwksUri();
            $jwks = $this->jwksLoader->load($jwksUri);
            $jwkSet = JWKSet::createFromKeyData($jwks);
            $jwsLoader = $this->createJwsLoader();
            $signature = null;
            $jwsLoader->loadAndVerifyWithKeySet((string)$token, $jwkSet, $signature);
        } catch (Throwable $e) {
            throw new UntrustedLogoutTokenException('Logout token signature validation failed: ' . $e->getMessage(), 0, $e);
        }
    }

    private function createJwsLoader(): JWSLoader
    {
        $idTokenSigningAlgorithms = $this->config->issuerMetadata()->idTokenSigningAlgValuesSupported();
        $algorithmManagerFactory = new AlgorithmManagerFactory(SignatureAlgorithmsFactory::create());

        return $this->jwsLoader ??= new JWSLoader(
            new JWSSerializerManager([new CompactSerializer()]),
            new JWSVerifier($algorithmManagerFactory->create($idTokenSigningAlgorithms)),
            new HeaderCheckerManager([new AlgorithmChecker($idTokenSigningAlgorithms)], [new JWSTokenSupport()]),
        );
    }

    /**
     * Validates standard JWT claims.
     *
     * @throws InvalidLogoutTokenException
     * @throws LogoutTokenExpiredException
     */
    private function validateClaims(LogoutToken $token): void
    {
        try {
            $this->createClaimCheckerManager()->check($token->claims(), $this->mandatoryClaims);
        } catch (Throwable $e) {
            // Check if this is an expiration error
            if (str_contains($e->getMessage(), 'exp')) {
                throw new LogoutTokenExpiredException('Logout token has expired', 0, $e);
            }
            throw new InvalidLogoutTokenException('Logout token claim validation failed: ' . $e->getMessage(), 0, $e);
        }
    }

    private function createClaimCheckerManager(): ClaimCheckerManager
    {
        return $this->claimCheckerManager ??= new ClaimCheckerManager([
            new IssuerChecker([$this->config->issuerMetadata()->issuer()]),
            new AudienceChecker($this->config->clientMetadata()->clientId()),
            new IssuedAtChecker($this->clock, $this->allowedTimeDrift),
            // Note: Logout tokens typically don't have exp claim, but if present, validate it
            new ExpirationTimeChecker($this->clock, $this->allowedTimeDrift, false), // not required
        ]);
    }

    /**
     * Validates logout-specific claims according to the specification.
     *
     * @throws InvalidLogoutTokenException
     */
    private function validateLogoutSpecificClaims(LogoutToken $token): void
    {
        // Validate that nonce is NOT present
        if ($token->has('nonce')) {
            throw new InvalidLogoutTokenException('Logout token must not contain a nonce claim');
        }

        // Validate events claim contains the logout event
        $events = $token->events();
        if (!isset($events[self::LOGOUT_EVENT_URI])) {
            throw new InvalidLogoutTokenException(
                'Logout token must contain the logout event: ' . self::LOGOUT_EVENT_URI
            );
        }

        // Validate that either sub or sid (or both) are present
        if ($token->subject() === null && $token->sessionId() === null) {
            throw new InvalidLogoutTokenException('Logout token must contain either sub or sid claim');
        }
    }
}
