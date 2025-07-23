<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
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
    private readonly ClaimCheckerManager $claimCheckerManager;
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
        private readonly array $mandatoryClaims = ['iss', 'sub', 'exp', 'iat'],
    ) {
        $this->claimCheckerManager = new ClaimCheckerManager([
            new IssuerChecker([$this->config->issuerMetadata()->issuer()]),
            new AudienceChecker($this->audience),
            new ExpirationTimeChecker($this->clock, $this->allowedTimeDrift),
            new IssuedAtChecker($this->clock, $this->allowedTimeDrift),
            new NotBeforeChecker($this->clock, $this->allowedTimeDrift),
        ]);
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

            $this->validateSignature($token);
            $this->validateClaims($claims);

            return new ValidatedAccessToken($token, $claims);
        } catch (Throwable $e) {
            throw new InvalidTokenException('Invalid Access Token: ' . $e->getMessage(), 0, $e);
        }
    }

    private function validateSignature(AccessToken $token): void
    {
        $jwksUri = $this->config->issuerMetadata()->jwksUri();
        $jwks = $this->jwksLoader->load($jwksUri);
        $jwkSet = JWKSet::createFromKeyData($jwks);
        $jwsLoader = $this->createJwsLoader();
        $signature = null;
        $jwsLoader->loadAndVerifyWithKeySet((string) $token, $jwkSet, $signature);

        if ($signature === null) {
            throw new InvalidTokenException('Token signature verification failed - no signature index returned');
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
     * @param array<string, mixed> $claims
     */
    private function validateClaims(array $claims): void
    {
        $this->claimCheckerManager->check($claims, $this->mandatoryClaims);
    }
}
