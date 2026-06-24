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
     * @param list<string> $mandatoryClaims
     */
    public function __construct(
        private readonly Config $config,
        private readonly JwksLoader $jwksLoader,
        private readonly string $audience,
        private readonly ClockInterface $clock = new SimpleClock(),
        private readonly int $allowedTimeDrift = 10,
        private readonly array $mandatoryClaims = ['iss', 'sub', 'aud', 'exp', 'iat'],
        private readonly ?string $expectedTokenType = null,
    ) {
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
        $idTokenSigningAlgorithms = $this->config->issuerMetadata()->idTokenSigningAlgValuesSupported();
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
        return $this->claimCheckerManager ??= new ClaimCheckerManager([
            new IssuerChecker([$this->config->issuerMetadata()->issuer()]),
            new AudienceChecker($this->audience),
            new ExpirationTimeChecker($this->clock, $this->allowedTimeDrift),
            new IssuedAtChecker($this->clock, $this->allowedTimeDrift),
            new NotBeforeChecker($this->clock, $this->allowedTimeDrift),
        ]);
    }
}
