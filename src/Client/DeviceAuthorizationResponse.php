<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Client;

use UnexpectedValueException;

/**
 * Response of a Device Authorization Request as defined by RFC 8628 section 3.2.
 */
final readonly class DeviceAuthorizationResponse
{
    public function __construct(
        private string $deviceCode,
        private string $userCode,
        private string $verificationUri,
        private int $expiresIn,
        private ?string $verificationUriComplete = null,
        private ?int $interval = null,
    ) {
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromResponse(array $data): self
    {
        $deviceCode = $data['device_code'] ?? null;

        if (!is_string($deviceCode) || $deviceCode === '') {
            throw new UnexpectedValueException('Device authorization response is missing "device_code".');
        }

        $userCode = $data['user_code'] ?? null;

        if (!is_string($userCode) || $userCode === '') {
            throw new UnexpectedValueException('Device authorization response is missing "user_code".');
        }

        $verificationUri = $data['verification_uri'] ?? null;

        if (!is_string($verificationUri) || $verificationUri === '') {
            throw new UnexpectedValueException('Device authorization response is missing "verification_uri".');
        }

        $expiresIn = $data['expires_in'] ?? null;

        if (!is_int($expiresIn)) {
            throw new UnexpectedValueException('Device authorization response is missing "expires_in".');
        }

        $verificationUriComplete = $data['verification_uri_complete'] ?? null;
        $verificationUriComplete = is_string($verificationUriComplete) ? $verificationUriComplete : null;

        $interval = $data['interval'] ?? null;
        $interval = is_int($interval) ? $interval : null;

        return new self(
            deviceCode: $deviceCode,
            userCode: $userCode,
            verificationUri: $verificationUri,
            expiresIn: $expiresIn,
            verificationUriComplete: $verificationUriComplete,
            interval: $interval,
        );
    }

    public function deviceCode(): string
    {
        return $this->deviceCode;
    }

    public function userCode(): string
    {
        return $this->userCode;
    }

    public function verificationUri(): string
    {
        return $this->verificationUri;
    }

    public function verificationUriComplete(): ?string
    {
        return $this->verificationUriComplete;
    }

    public function expiresIn(): int
    {
        return $this->expiresIn;
    }

    public function interval(): ?int
    {
        return $this->interval;
    }
}
