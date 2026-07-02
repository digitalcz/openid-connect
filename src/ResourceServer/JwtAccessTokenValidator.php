<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;
use DigitalCz\OpenIDConnect\Util\SignatureAlgorithmsFactory;
use DigitalCz\OpenIDConnect\Util\SimpleClock;
use InvalidArgumentException;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\CallableChecker;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * JWT access token validator
 */
final class JwtAccessTokenValidator implements AccessTokenValidator
{
    private ?ClaimCheckerManager $claimCheckerManager = null;
    private ?JWSLoader $jwsLoader = null;

    /**
     * @param string|list<string>|null $audience Expected token audience. A string matches a single audience
     *                                            (RFC 9068 §4); a list accepts a token whose "aud" matches any
     *                                            of the given values (a resource server with multiple identities);
     *                                            null skips audience validation entirely. Skipping is a deliberate
     *                                            deviation from RFC 9068 — the standards-correct way to accept a
     *                                            token issued for another audience is token exchange (RFC 8693).
     *                                            The presence of the "aud" claim is still governed by $mandatoryClaims.
     *                                            Must be null when $claimCheckers is provided.
     * @param list<string> $mandatoryClaims
     * @param list<ClaimChecker>|null $claimCheckers When provided, fully replaces the default claim checker set
     *                                               (issuer, audience, expiration, issued-at, not-before). Must be
     *                                               non-empty, each checker covering a distinct claim, and $audience
     *                                               must be null. Escape hatch for fully custom validation.
     */
    public function __construct(
        private readonly Config $config,
        private readonly JwksLoader $jwksLoader,
        private readonly string|array|null $audience,
        private readonly ClockInterface $clock = new SimpleClock(),
        private readonly int $allowedTimeDrift = 10,
        private readonly array $mandatoryClaims = ['iss', 'sub', 'aud', 'exp', 'iat'],
        private readonly ?string $expectedTokenType = null,
        private readonly ?array $claimCheckers = null,
    ) {
        if ($this->audience === []) {
            throw new InvalidArgumentException(
                '$audience must not be an empty list; use null to disable audience validation.',
            );
        }

        if ($this->claimCheckers !== null) {
            if ($this->audience !== null) {
                throw new InvalidArgumentException(
                    '$audience must be null when $claimCheckers is provided; the injected checkers replace it entirely.',
                );
            }

            if ($this->claimCheckers === []) {
                throw new InvalidArgumentException(
                    '$claimCheckers must not be empty; pass null to use the default claim checkers.',
                );
            }

            $seenClaims = [];

            foreach ($this->claimCheckers as $claimChecker) {
                // @phpstan-ignore instanceof.alwaysTrue (runtime guard; PHP arrays don't enforce the docblock's element type)
                if (!$claimChecker instanceof ClaimChecker) {
                    throw new InvalidArgumentException(
                        sprintf('Each element of $claimCheckers must implement %s.', ClaimChecker::class),
                    );
                }

                $claim = $claimChecker->supportedClaim();

                if (isset($seenClaims[$claim])) {
                    throw new InvalidArgumentException(
                        sprintf('Duplicate claim checker for claim "%s" in $claimCheckers.', $claim),
                    );
                }

                $seenClaims[$claim] = true;
            }
        }
    }

    /**
     * Support JWT tokens only
     */
    public function supports(AccessToken $token): bool
    {
        return $token instanceof JwtAccessToken;
    }

    /**
     * Validate JWT signature and claims
     */
    public function validate(AccessToken $token): ValidatedAccessToken
    {
        if (!$token instanceof JwtAccessToken) {
            throw new InvalidTokenException('Access token is not a JWT');
        }

        try {
            $claims = $token->claims();

            $jws = $this->validateSignature($token);
            $this->validateTokenType($jws);
            $this->validateClaims($claims);

            return new ValidatedAccessToken($token, $claims);
        } catch (Throwable $e) {
            throw new InvalidTokenException('Invalid Access Token: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the JWKS endpoint cannot be reached
     */
    private function validateSignature(AccessToken $token): JWS
    {
        $jwksUri = $this->config->issuerMetadata()->jwksUri();
        $jwks = $this->jwksLoader->load($jwksUri);
        $jwkSet = JWKSet::createFromKeyData($jwks);
        $jwsLoader = $this->createJwsLoader();
        $signature = null;

        return $jwsLoader->loadAndVerifyWithKeySet((string) $token, $jwkSet, $signature);
    }

    /**
     * Optionally enforce the JWT "typ" header (RFC 9068).
     *
     * Only applied when an expected token type is configured. The header MUST be
     * present and equal to the expected type; per RFC 9068 both the bare form
     * ("at+jwt") and the prefixed media type ("application/at+jwt") are accepted.
     * The comparison is case-insensitive, as media types are (RFC 9068 / RFC 2045).
     *
     * @throws InvalidTokenException if the typ header is missing or does not match
     */
    private function validateTokenType(JWS $jws): void
    {
        if ($this->expectedTokenType === null) {
            return;
        }

        $typ = $jws->getSignature(0)->getProtectedHeader()['typ'] ?? null;

        if (!is_string($typ)) {
            throw new InvalidTokenException('Missing typ header');
        }

        $typ = strtolower($typ);
        $normalized = str_starts_with($typ, 'application/')
            ? substr($typ, strlen('application/'))
            : $typ;

        if (!hash_equals(strtolower($this->expectedTokenType), $normalized)) {
            throw new InvalidTokenException('Unexpected token type');
        }
    }

    /**
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the discovery endpoint cannot be reached
     */
    private function createJwsLoader(): JWSLoader
    {
        $idTokenSigningAlgorithms = SignatureAlgorithmsFactory::restrictToAsymmetric(
            $this->config->issuerMetadata()->idTokenSigningAlgValuesSupported(),
        );
        $algorithmManagerFactory = new AlgorithmManagerFactory(SignatureAlgorithmsFactory::create());

        return $this->jwsLoader ??= new JWSLoader(
            new JWSSerializerManager([new CompactSerializer()]),
            new JWSVerifier($algorithmManagerFactory->create($idTokenSigningAlgorithms)),
            new HeaderCheckerManager([new AlgorithmChecker($idTokenSigningAlgorithms)], [new JWSTokenSupport()]),
        );
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the discovery endpoint cannot be reached
     */
    private function validateClaims(array $claims): void
    {
        $this->createClaimCheckerManager()->check($claims, $this->mandatoryClaims);
    }

    /**
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the discovery endpoint cannot be reached
     */
    private function createClaimCheckerManager(): ClaimCheckerManager
    {
        return $this->claimCheckerManager ??= new ClaimCheckerManager(
            $this->claimCheckers ?? $this->defaultClaimCheckers(),
        );
    }

    /**
     * @return list<ClaimChecker>
     *
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws NetworkException if the discovery endpoint cannot be reached
     */
    private function defaultClaimCheckers(): array
    {
        $checkers = [
            new IssuerChecker([$this->config->issuerMetadata()->issuer()]),
            new ExpirationTimeChecker($this->clock, $this->allowedTimeDrift),
            new IssuedAtChecker($this->clock, $this->allowedTimeDrift),
            new NotBeforeChecker($this->clock, $this->allowedTimeDrift),
        ];

        $audienceChecker = $this->createAudienceChecker();

        if ($audienceChecker !== null) {
            $checkers[] = $audienceChecker;
        }

        return $checkers;
    }

    /**
     * Build the "aud" claim checker for the configured audience.
     *
     * A single string uses web-token's {@see AudienceChecker}. A list accepts a token whose "aud"
     * matches any of the configured values (string aud must be one of them; array aud must intersect
     * them). Null disables the audience check.
     */
    private function createAudienceChecker(): ?ClaimChecker
    {
        if ($this->audience === null) {
            return null;
        }

        if (is_string($this->audience)) {
            return new AudienceChecker($this->audience);
        }

        $accepted = $this->audience;

        return new CallableChecker('aud', static function (mixed $aud) use ($accepted): bool {
            if (is_string($aud)) {
                return in_array($aud, $accepted, true);
            }

            if (is_array($aud)) {
                foreach ($aud as $value) {
                    if (is_string($value) && in_array($value, $accepted, true)) {
                        return true;
                    }
                }
            }

            return false;
        });
    }
}
