<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use RuntimeException;

/**
 * The databases the package runs on. Where their SQL differs, the package
 * branches on this. MySQL and MariaDB keep timestamps without a time zone,
 * so the package writes them in UTC there.
 */
enum DatabasePlatform
{
    case POSTGRESQL;
    case MYSQL;

    public static function of(Connection $connection): self
    {
        $platform = $connection->getDatabasePlatform();
        return match (true) {
            $platform instanceof PostgreSQLPlatform => self::POSTGRESQL,
            $platform instanceof AbstractMySQLPlatform => self::MYSQL,
            default => throw new RuntimeException(sprintf('The database platform %s is not supported, only PostgreSQL, MySQL and MariaDB are', $platform::class), 1795201327),
        };
    }

    /**
     * The SQL expression of the current time.
     */
    public function now(): string
    {
        return match ($this) {
            self::POSTGRESQL => 'now()',
            self::MYSQL => 'UTC_TIMESTAMP(6)',
        };
    }

    /**
     * A point in time as the parameter for a timestamp column.
     */
    public function timestamp(DateTimeInterface $time): string
    {
        return match ($this) {
            self::POSTGRESQL => $time->format(DATE_ATOM),
            self::MYSQL => DateTimeImmutable::createFromInterface($time)->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s.u'),
        };
    }
}
