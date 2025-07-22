<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use LogicException;

/**
 * Token validation orchestrator
 */
final readonly class ResourceServer
{
    /**
     * @param iterable<AccessTokenValidator> $validators
     */
    public function __construct(private iterable $validators)
    {
    }

    /**
     * Validate access token using appropriate validator
     */
    public function introspect(AccessToken $token): ValidatedAccessToken
    {
        return $this->getValidator($token)->validate($token);
    }

    private function getValidator(AccessToken $token): AccessTokenValidator
    {
        foreach ($this->validators as $validator) {
            if ($validator->supports($token)) {
                return $validator;
            }
        }

        throw new LogicException(sprintf('No AccessTokenValidator supporting %s.', $token::class));
    }
}
