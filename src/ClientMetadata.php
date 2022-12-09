<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Authentication\AuthenticationMethod;
use DigitalCz\OpenIDConnect\Authentication\ClientSecretPost;
use DigitalCz\OpenIDConnect\Exception\MissingParamException;

final class ClientMetadata
{
    public const CLIENT_ID = 'client_id';
    public const CLIENT_SECRET = 'client_secret';
    public const REDIRECT_URI = 'redirect_uri';

    public function __construct(
        private readonly string $id,
        private readonly ?string $secret = null,
        private readonly ?string $redirectUri = null,
        private readonly ?AuthenticationMethod $authenticationMethod = new ClientSecretPost()
    ) {
    }

    public function id(): string
    {
        return $this->id;
    }

    public function secret(): string
    {
        return $this->secret ?? throw new MissingParamException('client_secret');
    }

    public function redirectUri(): ?string
    {
        return $this->redirectUri;
    }

    public function authenticationMethod(): ?AuthenticationMethod
    {
        return $this->authenticationMethod;
    }
}
