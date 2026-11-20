<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Unit\League;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\MySQLPlatform;
use Flownative\OAuth2\Server\League\AuthorizationCodes;
use Flownative\OAuth2\Server\League\DbalRefreshTokenRepository;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * MySQL has no UPDATE … RETURNING, so a code or refresh token is locked and
 * read before it is marked spent. These tests check the order of the
 * statements; the functional tests check the locks against a real database.
 */
class SpendingOnMysqlTest extends TestCase
{
    private const string GRANT_IDENTIFIER = '0b6c5d1e-1111-4222-8333-444455556666';

    /**
     * @var list<string>
     */
    private array $statements = [];

    private bool $isInTransaction = false;

    /**
     * @return iterable<string, array{string}>
     */
    public static function credentials(): iterable
    {
        yield 'a code' => ['code'];
        yield 'a refresh token' => ['refresh token'];
    }

    #[Test]
    #[DataProvider('credentials')]
    public function theGrantIsLockedBeforeTheCredentialIsReadAndMarkedSpent(string $credential): void
    {
        $table = $credential === 'code' ? 'flownative_oauth2_server_authorization_code' : 'flownative_oauth2_server_refresh_token';
        $spent = $this->spend($credential, $this->connectionAnswering([
            'grant_id' => self::GRANT_IDENTIFIER,
            'redirect_uri' => 'https://client.test/callback',
            'code_challenge' => 'challenge',
            'access_token_digest' => str_repeat('a', 64),
            'client_id' => 'client',
            'resource' => 'https://server.test/mcp',
            'scopes' => '["mcp"]',
        ]));

        self::assertNotNull($spent);
        self::assertSame(self::GRANT_IDENTIFIER, $spent->grantIdentifier);
        self::assertCount(4, $this->statements);
        self::assertStringStartsWith('SELECT grant_id FROM ' . $table, $this->statements[0]);
        self::assertStringNotContainsString('FOR UPDATE', $this->statements[0]);
        self::assertStringStartsWith('SELECT grant_id FROM flownative_oauth2_server_grant', $this->statements[1]);
        self::assertStringEndsWith('FOR UPDATE', $this->statements[1]);
        self::assertStringContainsString('spent_at IS NULL', $this->statements[2]);
        self::assertStringEndsWith('FOR UPDATE', $this->statements[2]);
        self::assertStringStartsWith('UPDATE ' . $table . ' SET spent_at = UTC_TIMESTAMP(6)', $this->statements[3]);
    }

    #[Test]
    #[DataProvider('credentials')]
    public function aCredentialTheLockedReadDoesNotFindIsNotMarkedSpent(string $credential): void
    {
        self::assertNull($this->spend($credential, $this->connectionAnswering(false)));
        self::assertCount(3, $this->statements);
        self::assertStringStartsWith('SELECT', $this->statements[2], 'nothing is marked spent');
    }

    #[Test]
    #[DataProvider('credentials')]
    public function anUnknownCredentialLocksNothing(string $credential): void
    {
        self::assertNull($this->spend($credential, $this->connectionAnswering(false, false)));
        self::assertCount(1, $this->statements);
    }

    #[Test]
    #[DataProvider('credentials')]
    public function theReadsAfterASpendFoundNothingLockTheRows(string $credential): void
    {
        $statements = [];
        $connection = $this->createStub(Connection::class);
        $connection->method('getDatabasePlatform')->willReturn(new MySQLPlatform());
        $connection->method('fetchAssociative')->willReturnCallback(static function (string $sql) use (&$statements): false {
            $statements[] = $sql;
            return false;
        });
        $connection->method('fetchOne')->willReturnCallback(static function (string $sql) use (&$statements): false {
            $statements[] = $sql;
            return false;
        });

        if ($credential === 'code') {
            (new AuthorizationCodes($connection))->spentBefore('the-code');
        } else {
            (new DbalRefreshTokenRepository($connection))->spentBefore('the-refresh-token');
            (new DbalRefreshTokenRepository($connection))->wasSpentWithin('the-refresh-token', 3);
        }

        self::assertNotEmpty($statements);
        foreach ($statements as $statement) {
            self::assertStringEndsWith('FOR UPDATE', $statement, 'a plain read sees the snapshot from before the lock wait');
        }
    }

    private function spend(string $credential, Connection $connection): ?object
    {
        return $credential === 'code'
            ? (new AuthorizationCodes($connection))->spend('the-code')
            : (new DbalRefreshTokenRepository($connection))->spend('the-refresh-token');
    }

    /**
     * @param array<string, string>|false $lockedRow
     */
    private function connectionAnswering(array|false $lockedRow, string|false $grantIdentifier = self::GRANT_IDENTIFIER): Connection
    {
        $connection = $this->createStub(Connection::class);
        $connection->method('getDatabasePlatform')->willReturn(new MySQLPlatform());
        $connection->method('transactional')->willReturnCallback(function (callable $write) use ($connection): mixed {
            $this->isInTransaction = true;
            try {
                return $write($connection);
            } finally {
                $this->isInTransaction = false;
            }
        });
        $connection->method('fetchOne')->willReturnCallback(function (string $sql) use ($grantIdentifier): string|false {
            $this->record($sql);
            return $grantIdentifier;
        });
        $connection->method('fetchAssociative')->willReturnCallback(function (string $sql) use ($lockedRow): array|false {
            $this->record($sql);
            return $lockedRow;
        });
        $connection->method('executeStatement')->willReturnCallback(function (string $sql): int {
            $this->record($sql);
            return 1;
        });
        return $connection;
    }

    private function record(string $sql): void
    {
        self::assertTrue($this->isInTransaction, 'every statement of a spend runs in one transaction');
        $this->statements[] = trim((string)preg_replace('/\s+/', ' ', $sql));
    }
}
