<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Unit;

use DateTimeImmutable;
use DateTimeZone;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\MySQLPlatform;
use Flownative\OAuth2\Server\Grants;
use Flownative\OAuth2\Server\Issuer;
use Flownative\OAuth2\Server\PendingAuthorizationRequest;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

class GrantsTest extends TestCase
{
    #[Test]
    public function aSubjectLongerThanTheTablesTakeIsRefusedWithoutAQuery(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('getDatabasePlatform')->willReturn(new MySQLPlatform());
        $connection->expects(self::never())->method('executeStatement');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1795206411);
        (new Grants($connection))->create(self::request(), str_repeat('ä', 769));
    }

    #[Test]
    public function aSubjectOfTheLongestLengthIsStored(): void
    {
        $longest = str_repeat('ä', 768);
        $connection = $this->createMock(Connection::class);
        $connection->method('getDatabasePlatform')->willReturn(new MySQLPlatform());
        $connection->expects(self::once())->method('executeStatement')->with(self::anything(), self::callback(static fn (array $parameters): bool => $parameters['subject'] === $longest))->willReturn(1);

        self::assertNotSame('', (new Grants($connection))->create(self::request(), $longest));
    }

    #[Test]
    public function aGrantWithoutALifetimeIsStoredWithoutExpiry(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('getDatabasePlatform')->willReturn(new MySQLPlatform());
        $connection->expects(self::once())->method('executeStatement')->with(self::anything(), self::callback(static fn (array $parameters): bool => $parameters['expiresAt'] === null))->willReturn(1);

        (new Grants($connection))->create(self::request(), 'subject');
    }

    #[Test]
    public function aGrantExpiresAfterItsLifetime(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('getDatabasePlatform')->willReturn(new MySQLPlatform());
        $expiresAt = null;
        $connection->expects(self::once())->method('executeStatement')->with(self::anything(), self::callback(static function (array $parameters) use (&$expiresAt): bool {
            $expiresAt = $parameters['expiresAt'];
            return true;
        }))->willReturn(1);
        $grants = new Grants($connection);
        (new ReflectionProperty(Grants::class, 'lifetime'))->setValue($grants, 'P30D');

        $before = new DateTimeImmutable('+30 days', new DateTimeZone('UTC'));
        $grants->create(self::request(), 'subject');
        $after = new DateTimeImmutable('+30 days', new DateTimeZone('UTC'));

        self::assertIsString($expiresAt);
        $expiry = new DateTimeImmutable($expiresAt, new DateTimeZone('UTC'));
        self::assertGreaterThanOrEqual($before->getTimestamp(), $expiry->getTimestamp());
        self::assertLessThanOrEqual($after->getTimestamp(), $expiry->getTimestamp());
    }

    private static function request(): PendingAuthorizationRequest
    {
        return new PendingAuthorizationRequest(
            'request',
            Issuer::fromString('https://server.test'),
            'client',
            'Client',
            'https://client.test/callback',
            null,
            ['mcp'],
            'challenge',
            'https://server.test/mcp',
            new DateTimeImmutable('+10 minutes'),
        );
    }
}
