<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * PSR Clock implementation
 */
final class SimpleClock implements ClockInterface
{
    /**
     * Get current time
     */
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
