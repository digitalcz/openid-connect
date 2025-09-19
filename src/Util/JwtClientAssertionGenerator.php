<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Clock\ClockInterface;

/**
 * JWT client assertion generator for OAuth2 client authentication
 */
final class JwtClientAssertionGenerator
{
    public function __construct(
        private readonly ClockInterface $clock = new SimpleClock(),
    ) {
    }

    /**
     * Generate a client assertion JWT using client secret (HMAC)
     */
    public function generateWithSecret(
        string $clientId,
        string $audience,
        string $clientSecret,
        string $algorithm = 'HS256',
        int $expirationSeconds = 300,
    ): string {
        $jwk = JWKFactory::createFromSecret($clientSecret);

        return $this->generateJwt($clientId, $audience, $jwk, $algorithm, $expirationSeconds);
    }

    /**
     * Generate a client assertion JWT using private key (RSA/ECDSA)
     */
    public function generateWithPrivateKey(
        string $clientId,
        string $audience,
        string $privateKey,
        string $algorithm = 'RS256',
        int $expirationSeconds = 300,
    ): string {
        $jwk = JWKFactory::createFromKey($privateKey);

        return $this->generateJwt($clientId, $audience, $jwk, $algorithm, $expirationSeconds);
    }

    /**
     * Generate a client assertion JWT using JWK
     */
    public function generateWithJwk(
        string $clientId,
        string $audience,
        JWK $jwk,
        string $algorithm = 'RS256',
        int $expirationSeconds = 300,
    ): string {
        return $this->generateJwt($clientId, $audience, $jwk, $algorithm, $expirationSeconds);
    }

    private function generateJwt(
        string $clientId,
        string $audience,
        JWK $jwk,
        string $algorithm,
        int $expirationSeconds,
    ): string {
        $now = $this->clock->now()->getTimestamp();
        $exp = $now + $expirationSeconds;

        // JWT Header
        $header = [
            'alg' => $algorithm,
            'typ' => 'JWT',
        ];

        // Add kid if available
        if ($jwk->has('kid')) {
            $header['kid'] = $jwk->get('kid');
        }

        // JWT Payload
        $payload = [
            'iss' => $clientId,        // Issuer (client ID)
            'sub' => $clientId,        // Subject (client ID)
            'aud' => $audience,        // Audience (token endpoint)
            'jti' => $this->generateJti(), // JWT ID (unique identifier)
            'iat' => $now,             // Issued at
            'exp' => $exp,             // Expiration time
        ];

        // Create JWS builder
        $algorithmManagerFactory = new AlgorithmManagerFactory(SignatureAlgorithmsFactory::create());
        $algorithmManager = $algorithmManagerFactory->create([$algorithm]);

        $jwsBuilder = new JWSBuilder($algorithmManager);

        // Build and sign the JWT
        $jws = $jwsBuilder
            ->create()
            ->withPayload(Json::encode($payload))
            ->addSignature($jwk, $header)
            ->build();

        // Serialize to compact format
        $serializer = new CompactSerializer();

        return $serializer->serialize($jws, 0);
    }

    /**
     * Generate a unique JWT ID
     */
    private function generateJti(): string
    {
        return bin2hex(random_bytes(16));
    }
}
