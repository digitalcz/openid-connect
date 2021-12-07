<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Exception;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function Safe\sprintf;

class ResponseException extends RuntimeException
{
    public function __construct(private RequestInterface $request, private ResponseInterface $response)
    {
        $code = $response->getStatusCode();
        $url = (string)$this->request->getUri();
        $message = sprintf('HTTP %s returned for "%s".', $code, $url);

        parent::__construct($message, $code);
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
