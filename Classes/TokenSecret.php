<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

/**
 * Codes and tokens are random secrets the database knows only by their
 * SHA-256 digest; a stolen table holds nothing that can be presented.
 */
final class TokenSecret
{
    public static function generate(string $prefix = ''): string
    {
        return $prefix . bin2hex(random_bytes(32));
    }

    public static function digest(string $secret): string
    {
        return hash('sha256', $secret);
    }
}
