<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use DigitalCz\OpenIDConnect\Config\Config;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
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
 * JWT-based ID token validator
 */
final class JwtIdTokenValidator implements IdTokenValidator
{
    private readonly ClaimCheckerManager $claimCheckerManager;
    private ?JWSLoader $jwsLoader = null;

    /**
     * @param list<string> $mandatoryClaims
     */
    public function __construct(
        private readonly Config $config,
        private readonly JwksLoader $jwksLoader,
        private readonly ClockInterface $clock = new SimpleClock(),
        private readonly int $allowedTimeDrift = 10, // seconds
        private readonly array $mandatoryClaims = ['iss', 'sub', 'aud', 'exp', 'iat'],
    ) {
        $this->claimCheckerManager = new ClaimCheckerManager([
            new IssuerChecker([$this->config->issuerMetadata()->issuer()]),
            new AudienceChecker($this->config->clientMetadata()->clientId()),
            new ExpirationTimeChecker($this->clock, $this->allowedTimeDrift),
            new IssuedAtChecker($this->clock, $this->allowedTimeDrift),
            new NotBeforeChecker($this->clock, $this->allowedTimeDrift),
        ]);
    }

    /**
     * Validates ID token signature, claims, and nonce
     *
     * @throws InvalidTokenException
     */
    public function validate(IdToken $token, ?string $nonce = null): void
    {
        try {
            $this->validateSignature($token);
            $this->validateClaims($token);
            $this->validateNonce($token, $nonce);
        } catch (Throwable $e) {
            throw new InvalidTokenException('Invalid ID Token: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Validates token signature using JWKS
     *
     * @throws Exception
     */
    public function validateSignature(IdToken $token): void
    {
        $jwksUri = $this->config->issuerMetadata()->jwksUri();
        $jwks = $this->jwksLoader->load($jwksUri);
        $jwkSet = JWKSet::createFromKeyData($jwks);
        $jwsLoader = $this->createJwsLoader();
        $signature = null;
        $jwsLoader->loadAndVerifyWithKeySet((string)$token, $jwkSet, $signature);
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

    private function validateClaims(IdToken $token): void
    {
        $this->claimCheckerManager->check($token->claims(), $this->mandatoryClaims);
    }

    private function validateNonce(IdToken $token, ?string $nonce): void
    {
        if ($nonce === null) {
            return; // Nonce is optional, skip validation
        }

        if (!hash_equals($token->nonce(), $nonce)) {
            throw new InvalidTokenException('Nonce mismatch');
        }
    }
}
