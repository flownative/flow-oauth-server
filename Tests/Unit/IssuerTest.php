<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Unit;

use Flownative\OAuth2\Server\Issuer;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class IssuerTest extends TestCase
{
    #[Test]
    public function anIssuerIsSchemeAndHost(): void
    {
        $issuer = Issuer::fromString('https://acme.example.test');

        self::assertSame('https://acme.example.test/oauth/token', $issuer->uriOf('/oauth/token'));
        self::assertSame('http://localhost:8080', Issuer::fromString('http://localhost:8080')->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function noIssuers(): iterable
    {
        yield 'a trailing slash' => ['https://acme.example.test/'];
        yield 'a path' => ['https://acme.example.test/mcp'];
        yield 'a query' => ['https://acme.example.test?x=1'];
        yield 'another scheme' => ['ftp://acme.example.test'];
        yield 'no host' => ['https://'];
    }

    #[Test]
    #[DataProvider('noIssuers')]
    public function anythingElseIsRefused(string $value): void
    {
        $this->expectException(InvalidArgumentException::class);
        Issuer::fromString($value);
    }
}
