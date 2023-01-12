<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Authentication\ClientSecretBasic;
use DigitalCz\OpenIDConnect\Authentication\ClientSecretPost;
use DigitalCz\OpenIDConnect\Exception\AuthorizationException;
use DigitalCz\OpenIDConnect\Exception\RuntimeException;
use DigitalCz\OpenIDConnect\Grant\AuthorizationCode;
use DigitalCz\OpenIDConnect\Grant\RefreshToken;
use DigitalCz\OpenIDConnect\Http\AuthenticatedClient;
use DigitalCz\OpenIDConnect\Http\HttpClient;
use DigitalCz\OpenIDConnect\JOSE\NonceChecker;
use DigitalCz\OpenIDConnect\Param\AuthorizationParams;
use DigitalCz\OpenIDConnect\Param\CallbackChecks;
use DigitalCz\OpenIDConnect\Param\CallbackParams;
use DigitalCz\OpenIDConnect\Param\ClaimsChecks;
use DigitalCz\OpenIDConnect\Param\TokenParams;
use DigitalCz\OpenIDConnect\Token\Tokens;
use DigitalCz\OpenIDConnect\Token\TokenVerifierFactory;
use DigitalCz\OpenIDConnect\Token\TokenVerifierInterface;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;

final class Client
{
    public function __construct(private readonly Config $config, private readonly HttpClient $httpClient)
    {
    }

    /**
     * Create URL to redirect to authorization endpoint
     */
    public function getAuthorizationUrl(AuthorizationParams $params): UriInterface
    {
        return $this->httpClient
            ->createUri($this->getProviderMetadata()->authorizationEndpoint())
            ->withQuery($this->createAuthorizationQuery($params));
    }

    /**
     * Handle authorization response
     */
    public function handleCallback(CallbackParams $params, CallbackChecks $checks): Tokens
    {
        if ($params->error() !== null) {
            throw AuthorizationException::error($params->error(), $params->errorDescription());
        }

        if ($params->state() !== $checks->state()) {
            throw AuthorizationException::stateMismatch($checks->state(), $params->state());
        }

        $tokenParams = new TokenParams(new AuthorizationCode(), [
            TokenParams::CODE => $params->code(),
            ClientMetadata::REDIRECT_URI => $this->getClientMetadata()->redirectUri(),
        ]);
        $tokens = $this->requestTokens($tokenParams);

        if ($tokens->idToken() !== null) {
            $claimsChecks = new ClaimsChecks(
                ['aud', 'exp', 'iat', 'iss', 'sub'],
                [
                    new IssuerChecker([$this->getProviderMetadata()->issuer()]),
                    new AudienceChecker($this->getClientMetadata()->id()),
                    new ExpirationTimeChecker(10),
                    new IssuedAtChecker(10),
                    new NotBeforeChecker(10),
                    new NonceChecker($checks->nonce()),
                ],
            );
            $this->createTokenVerifier()->verify($tokens->idToken(), $claimsChecks);
        }

        return $tokens;
    }

    /**
     * Request for tokens
     */
    public function requestTokens(TokenParams $params): Tokens
    {
        $tokenEndpoint = $this->getProviderMetadata()->tokenEndpoint()
            ?? throw new AuthorizationException('Provider configuration is missing token_endpoint parameter');

        $request = $this->httpClient
            ->createRequest('POST', $tokenEndpoint)
            ->withHeader('content-type', 'application/x-www-form-urlencoded')
            ->withBody($this->httpClient->createStream($this->createTokenQuery($params)));

        $clientMetadata = $this->getClientMetadata();

        if ($clientMetadata->authenticationMethod() instanceof ClientSecretBasic) {
            $credentials = base64_encode($clientMetadata->id() . ":" . $clientMetadata->secret());

            /** @var RequestInterface $request */
            $request = $request->withHeader('Authorization', "Basic {$credentials}");
        }

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new AuthorizationException('Token request error: ' . $e->getMessage(), previous: $e);
        }

        try {
            $result = $this->httpClient->parseResponse($response);
        } catch (RuntimeException $e) {
            throw new AuthorizationException('Invalid response from token endpoint: ' . $e->getMessage(), previous: $e);
        }

        if (isset($result['error'])) {
            throw AuthorizationException::error($result['error'], $result['error_description'] ?? null);
        }

        return new Tokens($result);
    }

    /**
     * Refreshes the token if needed
     */
    public function refreshTokens(Tokens $tokens): Tokens
    {
        if (!$tokens->isExpired() || $tokens->refreshToken() === null) {
            return $tokens;
        }

        return $this->requestTokens(
            new TokenParams(
                new RefreshToken(),
                [
                    'refresh_token' => $tokens->refreshToken(),
                ],
            ),
        );
    }

    public function getAuthenticatedClient(Tokens $tokens): AuthenticatedClient
    {
        return new AuthenticatedClient($this, $this->httpClient, $tokens);
    }

    public function getConfig(): Config
    {
        return $this->config;
    }

    private function createAuthorizationQuery(AuthorizationParams $authorizationParams): string
    {
        $clientMetadata = $this->getClientMetadata();

        $params = $authorizationParams->all();
        $params[AuthorizationParams::RESPONSE_TYPE] ??= 'code';
        $params[ClientMetadata::REDIRECT_URI] ??= $clientMetadata->redirectUri();
        $params[ClientMetadata::CLIENT_ID] ??= $clientMetadata->id();

        return $this->httpClient->buildQueryString($params);
    }

    private function createTokenQuery(TokenParams $tokenParams): string
    {
        $grant = $tokenParams->grantType();
        $params = $tokenParams->all();
        $params[TokenParams::GRANT_TYPE] = $grant->getType();

        $clientMetadata = $this->getClientMetadata();

        if ($clientMetadata->authenticationMethod() instanceof ClientSecretPost) {
            $params[ClientMetadata::CLIENT_ID] = $clientMetadata->id();
            $params[ClientMetadata::CLIENT_SECRET] = $clientMetadata->secret();
        }

        return $this->httpClient->buildQueryString($params);
    }

    private function getProviderMetadata(): ProviderMetadata
    {
        return $this->config->providerMetadata();
    }

    private function getClientMetadata(): ClientMetadata
    {
        return $this->config->clientMetadata();
    }

    private function createTokenVerifier(): TokenVerifierInterface
    {
        return TokenVerifierFactory::create($this->getProviderMetadata());
    }
}
