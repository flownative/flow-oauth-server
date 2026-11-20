<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Client;

/**
 * Redirect URIs match on their parsed parts, except that a loopback redirect
 * matches on any port: a native client listens on a port of its own choosing
 * (RFC 8252). An address a browser could read differently than this parser,
 * with user info, a backslash or a character outside RFC 3986, is refused.
 */
final class RedirectUris
{
    private const array LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

    // An address is carried in every redirect and parsed again by whoever reads it, so it stays short.
    private const int MAXIMUM_LENGTH = 2048;

    private const string RFC_3986_CHARACTERS = '/^(?:[A-Za-z0-9\-._~:\/?#\[\]@!$&\'()*+,;=]|%[0-9A-Fa-f]{2})*$/D';

    private const string HTTP_URI = '~^(?<scheme>https?)://(?<host>\[[0-9A-Fa-f:.]+\]|(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+)(?::(?<port>[0-9]{1,5}))?(?<path>/[^?#]*)?(?:\?(?<query>[^#]*))?$~iD';

    /**
     * @param list<string> $registeredUris
     */
    public static function matches(string $presentedUri, array $registeredUris): bool
    {
        $presented = self::parts($presentedUri);
        if ($presented === null) {
            return false;
        }
        foreach ($registeredUris as $registeredUri) {
            $registered = self::parts($registeredUri);
            if ($registered === null) {
                continue;
            }
            if ($presented === $registered) {
                return true;
            }
            if (self::isLoopbackParts($presented) && self::isLoopbackParts($registered) && ['port' => null] + $presented === ['port' => null] + $registered) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a client may register the address: https, or http to a loopback host, never with user info or a fragment, and at most 2 kB long.
     */
    public static function isAcceptable(string $uri): bool
    {
        $parts = strlen($uri) > self::MAXIMUM_LENGTH ? null : self::parts($uri);
        return $parts !== null && ($parts['scheme'] === 'https' || self::isLoopbackParts($parts));
    }

    public static function isLoopback(string $uri): bool
    {
        $parts = self::parts($uri);
        return $parts !== null && self::isLoopbackParts($parts);
    }

    /**
     * @return string lower-cased, '' if the address is refused
     */
    public static function hostOf(string $uri): string
    {
        return self::parts($uri)['host'] ?? '';
    }

    /**
     * @return array{port: int|null, scheme: string, host: string, path: string, query: string|null}|null
     */
    private static function parts(string $uri): ?array
    {
        if (preg_match(self::RFC_3986_CHARACTERS, $uri) !== 1 || preg_match(self::HTTP_URI, $uri, $matches, PREG_UNMATCHED_AS_NULL) !== 1) {
            return null;
        }
        $port = $matches['port'] === null ? null : (int)$matches['port'];
        if ($port !== null && ($port < 1 || $port > 65535)) {
            return null;
        }
        return [
            'port' => $port,
            'scheme' => strtolower((string)$matches['scheme']),
            'host' => strtolower((string)$matches['host']),
            'path' => $matches['path'] ?? '/',
            'query' => $matches['query'],
        ];
    }

    /**
     * @param array{port: int|null, scheme: string, host: string, path: string, query: string|null} $parts
     */
    private static function isLoopbackParts(array $parts): bool
    {
        return $parts['scheme'] === 'http' && in_array($parts['host'], self::LOOPBACK_HOSTS, true);
    }
}
