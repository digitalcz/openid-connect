<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Authentication\ClientSecretBasic;
use DigitalCz\OpenIDConnect\Authentication\ClientSecretPost;
use DigitalCz\OpenIDConnect\Exception\AuthorizationException;
use DigitalCz\OpenIDConnect\Exception\HttpException;
use DigitalCz\OpenIDConnect\Exception\RuntimeException;
use DigitalCz\OpenIDConnect\Grant\AuthorizationCode;
use DigitalCz\OpenIDConnect\Http\AuthenticatedClient;
use DigitalCz\OpenIDConnect\Http\HttpClient;
use DigitalCz\OpenIDConnect\Param\AuthorizationParams;
use DigitalCz\OpenIDConnect\Param\CallbackChecks;
use DigitalCz\OpenIDConnect\Param\CallbackParams;
use DigitalCz\OpenIDConnect\Param\TokenParams;
use DigitalCz\OpenIDConnect\Token\Tokens;
use DigitalCz\OpenIDConnect\Token\TokenVerifierInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;

final class Client
{
    public function __construct(
        private Config $config,
        private HttpClient $httpClient,
        private TokenVerifierInterface $tokenVerifier
    ) {
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
            'code' => $params->code(),
            'redirect_uri' => $this->getClientMetadata()->redirectUri(),
        ]);
        $tokens = $this->requestTokens($tokenParams);

        if ($tokens->getIdToken() !== null) {
            $this->tokenVerifier->verify($tokens->getIdToken(), $checks);
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

    public function getAuthenticatedClient(Tokens $tokens): AuthenticatedClient
    {
        return new AuthenticatedClient($this, $this->httpClient, $tokens);
    }

    private function createAuthorizationQuery(AuthorizationParams $authorizationParams): string
    {
        $clientMetadata = $this->getClientMetadata();

        $params = $authorizationParams->all();
        $params['response_type'] ??= 'code';
        $params['redirect_uri'] ??= $clientMetadata->redirectUri();
        $params['client_id'] ??= $clientMetadata->id();

        return $this->httpClient->buildQueryString($params);
    }

    private function createTokenQuery(TokenParams $tokenParams): string
    {
        $grant = $tokenParams->getGrantType();
        $params = $tokenParams->all();
        $params['grant_type'] = $grant->getType();

        $clientMetadata = $this->getClientMetadata();

        if ($clientMetadata->authenticationMethod() instanceof ClientSecretPost) {
            $params['client_id'] = $clientMetadata->id();
            $params['client_secret'] = $clientMetadata->secret();
        }

        return $this->httpClient->buildQueryString($params);
    }

    private function getProviderMetadata(): ProviderMetadata
    {
        return $this->config->getProviderMetadata();
    }

    private function getClientMetadata(): ClientMetadata
    {
        return $this->config->getClientMetadata();
    }
}
