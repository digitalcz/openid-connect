<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\JOSE;

use DigitalCz\OpenIDConnect\Config;
use DigitalCz\OpenIDConnect\Exception\AuthorizationException;
use DigitalCz\OpenIDConnect\Param\CallbackChecks;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimExceptionInterface;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;

final class ClaimsChecker implements ClaimsCheckerInterface
{
    /**
     * @param string[] $mandatoryClaims
     */
    public function __construct(
        private Config $config,
        private array $mandatoryClaims = ['aud', 'exp', 'iat', 'iss', 'sub'],
        private int $clockTolerance = 10
    ) {
    }

    public function check(Claims $claims, CallbackChecks $checks): void
    {
        try {
            $this->createClaimCheckerManager($checks)->check($claims->all(), $this->mandatoryClaims);
        } catch (ClaimExceptionInterface $e) {
            throw new AuthorizationException('Invalid claims: ' . $e->getMessage(), previous: $e);
        }
    }

    private function createClaimCheckerManager(CallbackChecks $checks): ClaimCheckerManager
    {
        $providerMetadata = $this->config->getProviderMetadata();
        $clientMetadata = $this->config->getClientMetadata();

        return new ClaimCheckerManager([
            new IssuerChecker([$providerMetadata->issuer()]),
            new AudienceChecker($clientMetadata->id()),
            new ExpirationTimeChecker($this->clockTolerance),
            new IssuedAtChecker($this->clockTolerance),
            new NotBeforeChecker($this->clockTolerance),
            new NonceChecker($checks->nonce()),
        ]);
    }
}
