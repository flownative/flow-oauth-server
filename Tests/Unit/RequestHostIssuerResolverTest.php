<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Unit;

use Flownative\OAuth2\Server\RequestHostIssuerResolver;
use Flownative\OAuth2\Server\UnknownIssuerException;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class RequestHostIssuerResolverTest extends TestCase
{
    #[Test]
    public function anHttpsRequestNamesItsHostAsTheIssuer(): void
    {
        self::assertSame('https://server.test:8443', (new RequestHostIssuerResolver())->issuerFor(new ServerRequest('GET', 'https://server.test:8443/oauth/token'))->value);
    }

    #[Test]
    public function aPlainHttpRequestNamesNoIssuer(): void
    {
        $this->expectException(UnknownIssuerException::class);

        (new RequestHostIssuerResolver())->issuerFor(new ServerRequest('GET', 'http://server.test/oauth/token'));
    }
}
