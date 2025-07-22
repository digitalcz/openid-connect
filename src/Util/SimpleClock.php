<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

final class SimpleClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
