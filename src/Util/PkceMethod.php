<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect\Util;

/**
 * PKCE challenge method enumeration.
 *
 * @see RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients
 */
enum PkceMethod: string
{
    case Plain = 'plain';
    case S256 = 'S256';
}
