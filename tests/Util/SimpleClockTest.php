<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DateTimeImmutable;
use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Clock\ClockInterface;

#[CoversClass(SimpleClock::class)]
class SimpleClockTest extends TestCase
{
    public function testImplementsClockInterface(): void
    {
        $clock = new SimpleClock();

        $this->assertInstanceOf(ClockInterface::class, $clock);
    }

    public function testNowReturnsDateTimeImmutable(): void
    {
        $clock = new SimpleClock();
        $before = new DateTimeImmutable();

        $result = $clock->now();

        $after = new DateTimeImmutable();

        $this->assertInstanceOf(DateTimeImmutable::class, $result);

        // Verify the returned time is between before and after (within reasonable bounds)
        $this->assertGreaterThanOrEqual($before->getTimestamp(), $result->getTimestamp());
        $this->assertLessThanOrEqual($after->getTimestamp(), $result->getTimestamp());
    }

    public function testNowReturnsCurrentTime(): void
    {
        $clock = new SimpleClock();
        $currentTime = time();

        $result = $clock->now();

        // Allow for 2 second difference to account for execution time
        $timeDifference = abs($result->getTimestamp() - $currentTime);
        $this->assertLessThanOrEqual(2, $timeDifference);
    }

    public function testMultipleCallsReturnDifferentTimes(): void
    {
        $clock = new SimpleClock();

        $first = $clock->now();
        usleep(10000); // Sleep for 10ms to ensure different timestamps
        $second = $clock->now();

        $this->assertNotEquals($first, $second);
        $this->assertGreaterThanOrEqual($first->getTimestamp(), $second->getTimestamp());

        // Either different timestamps or different microseconds
        $timestampDiff = $second->getTimestamp() - $first->getTimestamp();
        $microDiff = (int) $second->format('u') - (int) $first->format('u');

        $this->assertTrue(
            $timestampDiff > 0 || $microDiff > 0,
            'Expected second call to return different time than first call',
        );
    }

    public function testNowReturnsImmutableObject(): void
    {
        $clock = new SimpleClock();
        $time1 = $clock->now();
        $time2 = $clock->now();

        // DateTimeImmutable objects should be different instances
        $this->assertNotSame($time1, $time2);

        // Verify they're truly immutable by checking class
        $this->assertInstanceOf(DateTimeImmutable::class, $time1);
        $this->assertInstanceOf(DateTimeImmutable::class, $time2);
    }

    public function testNowWithTimezone(): void
    {
        $clock = new SimpleClock();
        $result = $clock->now();

        // Should use system default timezone
        $this->assertInstanceOf(DateTimeImmutable::class, $result);

        // Verify timezone information is preserved
        $timezone = $result->getTimezone();
        $this->assertNotNull($timezone);
    }

    public function testConsistencyWithSystemTime(): void
    {
        $clock = new SimpleClock();

        // Get system time just before and after clock call
        $systemBefore = new DateTimeImmutable();
        $clockTime = $clock->now();
        $systemAfter = new DateTimeImmutable();

        // Clock time should be between system times
        $this->assertGreaterThanOrEqual(
            $systemBefore->getTimestamp(),
            $clockTime->getTimestamp(),
        );
        $this->assertLessThanOrEqual(
            $systemAfter->getTimestamp(),
            $clockTime->getTimestamp(),
        );
    }

    public function testHighPrecisionTiming(): void
    {
        $clock = new SimpleClock();

        $time1 = $clock->now();
        $time2 = $clock->now();

        // Even rapid successive calls should return different microseconds
        // (though this test might occasionally fail due to system timing)
        $microDiff = abs($time1->format('u') - $time2->format('u'));

        // Either different microseconds or different seconds
        $this->assertTrue(
            $microDiff > 0 || $time1->getTimestamp() !== $time2->getTimestamp(),
        );
    }
}
