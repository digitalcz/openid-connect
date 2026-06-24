<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\BackChannelLogout;

use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;
use DigitalCz\OpenIDConnect\Util\SignatureAlgorithmsFactory;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use Exception;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
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
 * JWT-based Back-Channel Logout Token validator.
 *
 * Validates logout tokens per the OpenID Connect Back-Channel Logout 1.0 specification.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
 */
final class JwtLogoutTokenValidator implements LogoutTokenValidator
{
    /**
     * Required value of the logout event URI inside the `events` claim.
     */
    public const string LOGOUT_EVENT_URI = 'http://schemas.openid.net/event/backchannel-logout';

    private ?ClaimCheckerManager $claimCheckerManager = null;
    private ?JWSLoader $jwsLoader = null;

    /**
     * @param list<string> $mandatoryClaims
     */
    public function __construct(
        private readonly Config $config,
        private readonly JwksLoader $jwksLoader,
        private readonly ClockInterface $clock = new SimpleClock(),
        private readonly int $allowedTimeDrift = 10,
        private readonly array $mandatoryClaims = ['iss', 'aud', 'iat', 'jti', 'events'],
    ) {
    }

    /**
     * Validates logout token signature, claims, and logout-specific requirements.
     *
     * @throws InvalidTokenException
     */
    public function validate(LogoutToken $token): void
    {
        try {
            $this->validateSignature($token);
            $this->validateClaims($token);
            $this->validateLogoutTokenClaims($token);
        } catch (Throwable $e) {
            throw new InvalidTokenException('Invalid Logout Token: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Validates logout token signature using JWKS.
     *
     * @throws Exception
     */
    public function validateSignature(LogoutToken $token): void
    {
        $jwksUri = $this->config->issuerMetadata()->jwksUri();
        $jwks = $this->jwksLoader->load($jwksUri);
        $jwkSet = JWKSet::createFromKeyData($jwks);
        $jwsLoader = $this->createJwsLoader();
        $signature = null;
        $jwsLoader->loadAndVerifyWithKeySet((string)$token, $jwkSet, $signature);
    }

    /**
     * Enforces logout-token-specific rules:
     *  - `events` claim is an object that includes the backchannel-logout event URI with an empty object value
     *  - `nonce` claim MUST NOT be present
     *  - At least one of `sub` or `sid` MUST be present
     *  - `sid` MUST be present when the client registered `backchannel_logout_session_required`
     *
     * @throws InvalidTokenException
     */
    public function validateLogoutTokenClaims(LogoutToken $token): void
    {
        if (!$token->has('events')) {
            throw new InvalidTokenException('Logout Token MUST contain an "events" claim');
        }

        $events = $token->events();

        if (!array_key_exists(self::LOGOUT_EVENT_URI, $events)) {
            throw new InvalidTokenException(
                sprintf('"events" claim must contain the "%s" member', self::LOGOUT_EVENT_URI),
            );
        }

        $logoutEvent = $events[self::LOGOUT_EVENT_URI];

        if (!is_array($logoutEvent)) {
            throw new InvalidTokenException(
                sprintf('"events" member "%s" must be an object', self::LOGOUT_EVENT_URI),
            );
        }

        if ($token->has('nonce')) {
            throw new InvalidTokenException('Logout Token MUST NOT contain a "nonce" claim');
        }

        if (!$token->has('sub') && !$token->has('sid')) {
            throw new InvalidTokenException('Logout Token MUST contain either a "sub" or "sid" claim');
        }

        if ($this->config->clientMetadata()->backchannelLogoutSessionRequired() && !$token->has('sid')) {
            throw new InvalidTokenException(
                'Logout Token MUST contain a "sid" claim because back-channel logout session is required',
            );
        }
    }

    /**
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the discovery endpoint cannot be reached
     */
    private function createJwsLoader(): JWSLoader
    {
        $signingAlgorithms = SignatureAlgorithmsFactory::restrictToAsymmetric(
            $this->config->issuerMetadata()->idTokenSigningAlgValuesSupported(),
        );
        $algorithmManagerFactory = new AlgorithmManagerFactory(SignatureAlgorithmsFactory::create());

        return $this->jwsLoader ??= new JWSLoader(
            new JWSSerializerManager([new CompactSerializer()]),
            new JWSVerifier($algorithmManagerFactory->create($signingAlgorithms)),
            new HeaderCheckerManager([new AlgorithmChecker($signingAlgorithms)], [new JWSTokenSupport()]),
        );
    }

    /**
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the discovery endpoint cannot be reached
     */
    private function validateClaims(LogoutToken $token): void
    {
        $this->createClaimCheckerManager()->check($token->claims(), $this->mandatoryClaims);
    }

    /**
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the discovery endpoint cannot be reached
     */
    private function createClaimCheckerManager(): ClaimCheckerManager
    {
        return $this->claimCheckerManager ??= new ClaimCheckerManager([
            new IssuerChecker([$this->config->issuerMetadata()->issuer()]),
            new AudienceChecker($this->config->clientMetadata()->clientId()),
            new ExpirationTimeChecker($this->clock, $this->allowedTimeDrift),
            new IssuedAtChecker($this->clock, $this->allowedTimeDrift),
            new NotBeforeChecker($this->clock, $this->allowedTimeDrift),
        ]);
    }
}
