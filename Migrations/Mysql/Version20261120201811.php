<?php

declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Indexes for the garbage collection on MySQL and MariaDB. Without them,
 * a DELETE by expiry scans the whole table and InnoDB locks every row it
 * scans, which blocks the token exchanges meanwhile.
 */
final class Version20261120201811 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Index the columns the garbage collection of the OAuth 2 authorization server deletes by';
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

        $this->addSql('CREATE INDEX flownative_oauth2_server_authorization_request_by_expiry ON flownative_oauth2_server_authorization_request (expires_at)');
        $this->addSql('CREATE INDEX flownative_oauth2_server_authorization_code_by_expiry ON flownative_oauth2_server_authorization_code (expires_at)');
        $this->addSql('CREATE INDEX flownative_oauth2_server_access_token_by_expiry ON flownative_oauth2_server_access_token (expires_at)');
        $this->addSql('CREATE INDEX flownative_oauth2_server_refresh_token_by_expiry ON flownative_oauth2_server_refresh_token (expires_at)');
        $this->addSql('CREATE INDEX flownative_oauth2_server_refresh_token_by_revocation ON flownative_oauth2_server_refresh_token (revoked_at)');
        $this->addSql('CREATE INDEX flownative_oauth2_server_client_by_expiry ON flownative_oauth2_server_client (origin, expires_at)');
        $this->addSql('CREATE INDEX flownative_oauth2_server_client_by_creation ON flownative_oauth2_server_client (origin, created_at)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!($this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform), 'Migration can only be executed safely on "mysql".');

        $this->addSql('DROP INDEX flownative_oauth2_server_client_by_creation ON flownative_oauth2_server_client');
        $this->addSql('DROP INDEX flownative_oauth2_server_client_by_expiry ON flownative_oauth2_server_client');
        $this->addSql('DROP INDEX flownative_oauth2_server_refresh_token_by_revocation ON flownative_oauth2_server_refresh_token');
        $this->addSql('DROP INDEX flownative_oauth2_server_refresh_token_by_expiry ON flownative_oauth2_server_refresh_token');
        $this->addSql('DROP INDEX flownative_oauth2_server_access_token_by_expiry ON flownative_oauth2_server_access_token');
        $this->addSql('DROP INDEX flownative_oauth2_server_authorization_code_by_expiry ON flownative_oauth2_server_authorization_code');
        $this->addSql('DROP INDEX flownative_oauth2_server_authorization_request_by_expiry ON flownative_oauth2_server_authorization_request');
    }
}
