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
        private readonly array $mandatoryClaims = ['iss', 'sub', 'aud', 'exp', 'iat'],
    ) {
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
            $this->validateAuthorizedParty($token);
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
        $idTokenSigningAlgorithms = array_values(array_intersect(
            $this->config->issuerMetadata()->idTokenSigningAlgValuesSupported(),
            SignatureAlgorithmsFactory::asymmetricAlgorithmNames(),
        ));
        $algorithmManagerFactory = new AlgorithmManagerFactory(SignatureAlgorithmsFactory::create());

        return $this->jwsLoader ??= new JWSLoader(
            new JWSSerializerManager([new CompactSerializer()]),
            new JWSVerifier($algorithmManagerFactory->create($idTokenSigningAlgorithms)),
            new HeaderCheckerManager([new AlgorithmChecker($idTokenSigningAlgorithms)], [new JWSTokenSupport()]),
        );
    }

    private function validateClaims(IdToken $token): void
    {
        $this->createClaimCheckerManager()->check($token->claims(), $this->mandatoryClaims);
    }

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

    /**
     * Validates the "azp" (authorized party) claim per OIDC Core 3.1.3.7.
     *
     * If the ID token has multiple audiences, "azp" MUST be present. When "azp"
     * is present, it MUST equal this client's client_id.
     *
     * @throws InvalidTokenException
     */
    private function validateAuthorizedParty(IdToken $token): void
    {
        $claims = $token->claims();
        $clientId = $this->config->clientMetadata()->clientId();

        $audience = $claims['aud'] ?? null;
        $hasMultipleAudiences = is_array($audience) && count($audience) > 1;

        $azp = $claims['azp'] ?? null;

        if ($azp === null) {
            if ($hasMultipleAudiences) {
                throw new InvalidTokenException('Missing azp claim for multi-audience ID token');
            }

            return;
        }

        if (!is_string($azp) || !hash_equals($clientId, $azp)) {
            throw new InvalidTokenException('Invalid azp claim');
        }
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
