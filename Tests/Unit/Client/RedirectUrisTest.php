<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Unit\Client;

use Flownative\OAuth2\Server\Client\RedirectUris;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class RedirectUrisTest extends TestCase
{
    /**
     * @return iterable<string, array{string, list<string>, bool}>
     */
    public static function redirects(): iterable
    {
        yield 'the exact address' => ['https://client.test/callback', ['https://client.test/callback'], true];
        yield 'another path' => ['https://client.test/other', ['https://client.test/callback'], false];
        yield 'another port of an https address' => ['https://client.test:8443/callback', ['https://client.test/callback'], false];
        yield 'a trailing slash' => ['https://client.test/callback/', ['https://client.test/callback'], false];
        yield 'localhost on another port' => ['http://localhost:53682/callback', ['http://localhost/callback'], true];
        yield 'IPv4 loopback on another port' => ['http://127.0.0.1:1234/callback', ['http://127.0.0.1:9999/callback'], true];
        yield 'IPv6 loopback on another port' => ['http://[::1]:1234/callback', ['http://[::1]/callback'], true];
        yield 'loopback with another path' => ['http://localhost:1234/other', ['http://localhost/callback'], false];
        yield 'loopback to another loopback host' => ['http://127.0.0.1:1234/callback', ['http://localhost/callback'], false];
        yield 'loopback over https on another port' => ['https://localhost:1234/callback', ['https://localhost/callback'], false];
        yield 'a backslash before user info' => ['http://evil.test\\@localhost/callback', ['http://localhost/callback'], false];
        yield 'a backslash before user info on https' => ['https://evil.test\\@client.test/callback', ['https://client.test/callback'], false];
        yield 'user info' => ['http://evil.test@localhost/callback', ['http://localhost/callback'], false];
        yield 'user and password' => ['https://user:secret@client.test/callback', ['https://client.test/callback'], false];
        yield 'an encoded backslash in the host' => ['http://evil.test%5C@localhost/callback', ['http://localhost/callback'], false];
        yield 'an encoded at sign in the host' => ['http://evil.test%40localhost/callback', ['http://localhost/callback'], false];
        yield 'an at sign in the path' => ['http://localhost:1234/callback@evil.test', ['http://localhost/callback'], false];
        yield 'an at sign in the path of the registered address' => ['http://localhost:1234/callback@evil.test', ['http://localhost/callback@evil.test'], true];
        yield 'a backslash in the path' => ['https://client.test/callback\\..\\x', ['https://client.test/callback\\..\\x'], false];
        yield 'an unencoded space' => ['https://client.test/call back', ['https://client.test/call back'], false];
        yield 'a malformed percent escape' => ['https://client.test/callback%zz', ['https://client.test/callback%zz'], false];
        yield 'an upper-case host' => ['https://CLIENT.test/callback', ['https://client.test/callback'], true];
        yield 'an upper-case loopback host' => ['http://LOCALHOST:1234/callback', ['http://localhost/callback'], true];
        yield 'an upper-case path' => ['https://client.test/Callback', ['https://client.test/callback'], false];
        yield 'a trailing dot on the host' => ['https://client.test./callback', ['https://client.test/callback'], false];
        yield 'a trailing dot on the loopback host' => ['http://localhost.:1234/callback', ['http://localhost/callback'], false];
        yield 'IPv6 loopback in another notation' => ['http://[0:0:0:0:0:0:0:1]:1234/callback', ['http://[::1]/callback'], false];
        yield 'IPv6 loopback without a port' => ['http://[::1]/callback', ['http://[::1]:8080/callback'], true];
        yield 'a fragment' => ['https://client.test/callback#x', ['https://client.test/callback#x'], false];
        yield 'another query' => ['http://localhost:1234/callback?a=2', ['http://localhost/callback?a=1'], false];
        yield 'the same query' => ['http://localhost:1234/callback?a=1', ['http://localhost/callback?a=1'], true];
        yield 'a port out of range' => ['https://client.test:99999/callback', ['https://client.test:99999/callback'], false];
    }

    /**
     * @param list<string> $registered
     */
    #[Test]
    #[DataProvider('redirects')]
    public function aRedirectMatchesExactlyOrAsLoopbackOnAnyPort(string $presented, array $registered, bool $expected): void
    {
        self::assertSame($expected, RedirectUris::matches($presented, $registered));
    }

    #[Test]
    public function onlyHttpsAndLoopbackAreAccepted(): void
    {
        self::assertTrue(RedirectUris::isAcceptable('https://claude.ai/api/mcp/auth_callback'));
        self::assertTrue(RedirectUris::isAcceptable('http://127.0.0.1/callback'));
        self::assertFalse(RedirectUris::isAcceptable('http://client.test/callback'));
        self::assertFalse(RedirectUris::isAcceptable('https://client.test/callback#fragment'));
        self::assertFalse(RedirectUris::isAcceptable('javascript:alert(1)'));
        self::assertFalse(RedirectUris::isAcceptable('https://user@client.test/callback'));
        self::assertFalse(RedirectUris::isAcceptable('http://evil.test\\@localhost/callback'));
        self::assertFalse(RedirectUris::isAcceptable('http://evil.test%5C@localhost/callback'));
        self::assertFalse(RedirectUris::isAcceptable('http://localhost./callback'));
        self::assertFalse(RedirectUris::isAcceptable('https://client.test/call back'));
        self::assertTrue(RedirectUris::isAcceptable('http://[::1]:8080/callback'));
        self::assertTrue(RedirectUris::isAcceptable('HTTP://LocalHost/callback'));
        self::assertTrue(RedirectUris::isAcceptable('https://client.test/callback?' . str_repeat('a', 2019)));
        self::assertFalse(RedirectUris::isAcceptable('https://client.test/callback?' . str_repeat('a', 2030)), 'an address longer than 2 kB');
    }
}
