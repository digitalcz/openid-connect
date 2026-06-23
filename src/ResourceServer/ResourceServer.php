<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\ResourceServer;

use DigitalCz\OpenIDConnect\Exception\ConfigurationException;
use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Exception\IntrospectionException;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use DigitalCz\OpenIDConnect\Exception\NetworkException;

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
     *
     * @throws ConfigurationException if no configured validator supports the token type
     * @throws DiscoveryException if provider metadata cannot be resolved
     * @throws IntrospectionException if the introspection endpoint request fails (opaque tokens)
     * @throws InvalidTokenException if the token is malformed, unsupported, or fails validation
     * @throws NetworkException if a required endpoint cannot be reached
     */
    public function introspect(AccessToken $token): ValidatedAccessToken
    {
        return $this->getValidator($token)->validate($token);
    }

    /**
     * @throws ConfigurationException if no configured validator supports the token type
     */
    private function getValidator(AccessToken $token): AccessTokenValidator
    {
        foreach ($this->validators as $validator) {
            if ($validator->supports($token)) {
                return $validator;
            }
        }

        throw new ConfigurationException(sprintf('No AccessTokenValidator supporting %s.', $token::class));
    }
}
