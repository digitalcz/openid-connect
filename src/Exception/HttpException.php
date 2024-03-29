<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class HttpException extends RuntimeException implements ClientExceptionInterface
{
    public function __construct(
        private readonly RequestInterface $request,
        private readonly ResponseInterface $response,
    ) {
        parent::__construct(sprintf(
            '%s %s returned for %s %s %s',
            $response->getStatusCode(),
            $response->getReasonPhrase(),
            $request->getMethod(),
            $request->getUri(),
            $response->getBody(),
        ));
    }

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }

    public function getResponse(): ResponseInterface
    {
        return $this->response;
    }
}
