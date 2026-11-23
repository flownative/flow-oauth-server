<?php

declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The point in time after which a grant is no longer good, for a configured
 * grant lifetime. Grants without one live until they are revoked.
 */
final class Version20261121090100 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Add the expiry of a grant of the OAuth 2 authorization server';
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

        $this->addSql('ALTER TABLE flownative_oauth2_server_grant ADD expires_at DATETIME(6) NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!($this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform), 'Migration can only be executed safely on "mysql".');

        $this->addSql('ALTER TABLE flownative_oauth2_server_grant DROP COLUMN expires_at');
    }
}
