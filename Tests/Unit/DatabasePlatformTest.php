<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Unit;

use DateTimeImmutable;
use DateTimeZone;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Platforms\MariaDBPlatform;
use Doctrine\DBAL\Platforms\MySQLPlatform;
use Doctrine\DBAL\Platforms\OraclePlatform;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Flownative\OAuth2\Server\DatabasePlatform;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class DatabasePlatformTest extends TestCase
{
    /**
     * @return iterable<string, array{AbstractPlatform, DatabasePlatform}>
     */
    public static function platforms(): iterable
    {
        yield 'PostgreSQL' => [new PostgreSQLPlatform(), DatabasePlatform::POSTGRESQL];
        yield 'MySQL' => [new MySQLPlatform(), DatabasePlatform::MYSQL];
        yield 'MariaDB' => [new MariaDBPlatform(), DatabasePlatform::MYSQL];
    }

    #[Test]
    #[DataProvider('platforms')]
    public function theConnectionTellsThePlatform(AbstractPlatform $platform, DatabasePlatform $expected): void
    {
        self::assertSame($expected, DatabasePlatform::of($this->connectionTo($platform)));
    }

    #[Test]
    public function anotherPlatformIsRefused(): void
    {
        $this->expectException(RuntimeException::class);
        DatabasePlatform::of($this->connectionTo(new OraclePlatform()));
    }

    #[Test]
    public function mysqlTakesTheCurrentTimeInUtc(): void
    {
        self::assertSame('now()', DatabasePlatform::POSTGRESQL->now());
        self::assertSame('UTC_TIMESTAMP(6)', DatabasePlatform::MYSQL->now());
    }

    #[Test]
    public function aTimestampForMysqlIsInUtcWithMicroseconds(): void
    {
        $time = new DateTimeImmutable('2026-11-20 12:00:00.123456', new DateTimeZone('Europe/Berlin'));

        self::assertSame('2026-11-20 11:00:00.123456', DatabasePlatform::MYSQL->timestamp($time));
    }

    #[Test]
    public function aTimestampForPostgresqlKeepsItsOffset(): void
    {
        $time = new DateTimeImmutable('2026-11-20 12:00:00.123456', new DateTimeZone('Europe/Berlin'));

        self::assertSame('2026-11-20T12:00:00+01:00', DatabasePlatform::POSTGRESQL->timestamp($time));
    }

    private function connectionTo(AbstractPlatform $platform): Connection
    {
        $connection = $this->createStub(Connection::class);
        $connection->method('getDatabasePlatform')->willReturn($platform);
        return $connection;
    }
}
