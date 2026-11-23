<?php

declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The point in time after which a grant is no longer good, for a configured
 * grant lifetime. Grants without one live until they are revoked.
 */
final class Version20261121090000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Add the expiry of a grant of the OAuth 2 authorization server';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(!($this->connection->getDatabasePlatform() instanceof PostgreSQLPlatform));

        $this->addSql('ALTER TABLE flownative_oauth2_server_grant ADD COLUMN expires_at timestamptz NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!($this->connection->getDatabasePlatform() instanceof PostgreSQLPlatform));

        $this->addSql('ALTER TABLE flownative_oauth2_server_grant DROP COLUMN expires_at');
    }
}
