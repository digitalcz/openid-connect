<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Authentication\AuthenticationMethod;
use DigitalCz\OpenIDConnect\Authentication\ClientSecretBasic;
use DigitalCz\OpenIDConnect\Authentication\ClientSecretPost;

final class ClientMetadata
{
    private AuthenticationMethod $authenticationMethod;

    public function __construct(
        private string $id,
        private string $secret,
        private ?string $redirectUri = null,
        ?AuthenticationMethod $authenticationMethod = null
    ) {
        $this->authenticationMethod = $authenticationMethod ?? new ClientSecretPost();
    }

    public function id(): string
    {
        return $this->id;
    }

    public function secret(): string
    {
        return $this->secret;
    }

    public function redirectUri(): ?string
    {
        return $this->redirectUri;
    }

    public function authenticationMethod(): AuthenticationMethod
    {
        return $this->authenticationMethod;
    }
}
