<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

use DigitalCz\OpenIDConnect\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(SignatureAlgorithmsFactory::class)]
class SignatureAlgorithmsFactoryTest extends TestCase
{
    public function testCreateRegistersBothSymmetricAndAsymmetricAlgorithms(): void
    {
        $names = array_keys(iterator_to_array(SignatureAlgorithmsFactory::create()));

        $this->assertContains('RS256', $names);
        $this->assertContains('ES256', $names);
        $this->assertContains('EdDSA', $names);
        $this->assertContains('HS256', $names); // still available for client_secret_jwt signing
    }

    public function testAsymmetricAlgorithmNamesExcludeHmac(): void
    {
        $names = SignatureAlgorithmsFactory::asymmetricAlgorithmNames();

        $this->assertContains('RS256', $names);
        $this->assertContains('PS256', $names);
        $this->assertContains('ES256', $names);
        $this->assertContains('EdDSA', $names);

        $this->assertNotContains('HS256', $names);
        $this->assertNotContains('HS384', $names);
        $this->assertNotContains('HS512', $names);
    }
}
