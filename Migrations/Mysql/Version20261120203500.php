<?php

declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Compares the identifiers, digests and issuers on MySQL and MariaDB without
 * padding, as PostgreSQL does. With utf8mb4_bin, a PAD SPACE collation,
 * 'X ' equals 'X'. MySQL names the NO PAD binary collation utf8mb4_0900_bin,
 * MariaDB utf8mb4_nopad_bin; the migration takes the one the server has.
 */
final class Version20261120203500 extends AbstractMigration
{
    /**
     * The columns compared with values from a request, by table.
     */
    private const array COLUMNS = [
        'flownative_oauth2_server_client' => [
            'client_id' => 'VARCHAR(768) NOT NULL',
        ],
        'flownative_oauth2_server_authorization_request' => [
            'request_id' => 'VARCHAR(64) NOT NULL',
            'issuer' => 'TEXT NOT NULL',
        ],
        'flownative_oauth2_server_grant' => [
            'subject' => 'VARCHAR(768) NOT NULL',
            'client_id' => 'VARCHAR(768) NOT NULL',
            'issuer' => 'TEXT NOT NULL',
        ],
        'flownative_oauth2_server_authorization_code' => [
            'code_digest' => 'VARCHAR(64) NOT NULL',
        ],
        'flownative_oauth2_server_access_token' => [
            'token_digest' => 'VARCHAR(64) NOT NULL',
            'resource' => 'TEXT NOT NULL',
        ],
        'flownative_oauth2_server_refresh_token' => [
            'token_digest' => 'VARCHAR(64) NOT NULL',
            'access_token_digest' => 'VARCHAR(64) NOT NULL',
        ],
    ];

    public function getDescription(): string
    {
        return 'Compare the identifiers of the OAuth 2 authorization server without padding';
    }

    /**
     * MySQL commits implicitly before and after every DDL statement, so a
     * transaction around the migration would end early and stay open in
     * the bookkeeping of the connection.
     */
    public function isTransactional(): bool
    {
        return false;
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(!($this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform), 'Migration can only be executed safely on "mysql".');

        $this->changeCollationTo($this->noPadBinaryCollation());
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!($this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform), 'Migration can only be executed safely on "mysql".');

        $this->changeCollationTo('utf8mb4_bin');
    }

    private function noPadBinaryCollation(): string
    {
        $collations = $this->connection->fetchFirstColumn(
            "SELECT COLLATION_NAME FROM information_schema.COLLATIONS WHERE COLLATION_NAME IN ('utf8mb4_0900_bin', 'utf8mb4_nopad_bin')"
        );
        $this->abortIf($collations === [], 'The server has no NO PAD binary collation, which needs MySQL 8.0.17 or MariaDB 10.2 or later.');
        return in_array('utf8mb4_0900_bin', $collations, true) ? 'utf8mb4_0900_bin' : 'utf8mb4_nopad_bin';
    }

    private function changeCollationTo(string $collation): void
    {
        foreach (self::COLUMNS as $table => $columns) {
            $changes = [sprintf('DEFAULT CHARACTER SET utf8mb4 COLLATE %s', $collation)];
            foreach ($columns as $column => $definition) {
                $changes[] = sprintf('MODIFY %s %s', $column, str_replace(' NOT NULL', " CHARACTER SET utf8mb4 COLLATE {$collation} NOT NULL", $definition));
            }
            $this->addSql(sprintf('ALTER TABLE %s %s', $table, implode(', ', $changes)));
        }
    }
}
