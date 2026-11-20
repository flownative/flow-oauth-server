<?php

declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The tables of the authorization server on MySQL and MariaDB, equal to the
 * PostgreSQL ones. Timestamps are DATETIME in UTC, which the package writes
 * explicitly. Text compares binary, as it does on PostgreSQL. Identifiers
 * which are keys are limited to 768 characters, the longest an index takes.
 */
final class Version20261120190207 extends AbstractMigration
{
    private const string TABLE_OPTIONS = 'ENGINE = InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin';

    public function getDescription(): string
    {
        return 'Create the tables of the OAuth 2 authorization server';
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

        $this->addSql("CREATE TABLE flownative_oauth2_server_client (
            client_id VARCHAR(768) NOT NULL PRIMARY KEY,
            client_name TEXT NOT NULL,
            redirect_uris JSON NOT NULL,
            origin VARCHAR(32) NOT NULL CHECK (origin IN ('registration', 'metadata_document')),
            registered_from TEXT NULL,
            created_at DATETIME(6) NOT NULL,
            expires_at DATETIME(6) NULL
        ) " . self::TABLE_OPTIONS);

        $this->addSql('CREATE TABLE flownative_oauth2_server_authorization_request (
            request_id VARCHAR(64) NOT NULL PRIMARY KEY,
            issuer TEXT NOT NULL,
            client_id TEXT NOT NULL,
            client_name TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            state TEXT NULL,
            scopes JSON NOT NULL,
            code_challenge TEXT NOT NULL,
            resource TEXT NOT NULL,
            created_at DATETIME(6) NOT NULL,
            expires_at DATETIME(6) NOT NULL
        ) ' . self::TABLE_OPTIONS);

        $this->addSql('CREATE TABLE flownative_oauth2_server_grant (
            grant_id CHAR(36) NOT NULL PRIMARY KEY,
            subject VARCHAR(768) NOT NULL,
            client_id VARCHAR(768) NOT NULL,
            client_name TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            issuer TEXT NOT NULL,
            resource TEXT NOT NULL,
            scopes JSON NOT NULL,
            created_at DATETIME(6) NOT NULL,
            last_used_at DATETIME(6) NULL,
            revoked_at DATETIME(6) NULL,
            INDEX flownative_oauth2_server_grant_by_subject (subject),
            INDEX flownative_oauth2_server_grant_by_client (client_id)
        ) ' . self::TABLE_OPTIONS);

        $this->addSql('CREATE TABLE flownative_oauth2_server_authorization_code (
            code_digest VARCHAR(64) NOT NULL PRIMARY KEY,
            grant_id CHAR(36) NOT NULL,
            redirect_uri TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            created_at DATETIME(6) NOT NULL,
            expires_at DATETIME(6) NOT NULL,
            spent_at DATETIME(6) NULL,
            INDEX flownative_oauth2_server_authorization_code_by_grant (grant_id),
            CONSTRAINT flownative_oauth2_server_authorization_code_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES flownative_oauth2_server_grant (grant_id) ON DELETE CASCADE
        ) ' . self::TABLE_OPTIONS);

        $this->addSql('CREATE TABLE flownative_oauth2_server_access_token (
            token_digest VARCHAR(64) NOT NULL PRIMARY KEY,
            grant_id CHAR(36) NOT NULL,
            resource TEXT NOT NULL,
            scopes JSON NOT NULL,
            created_at DATETIME(6) NOT NULL,
            expires_at DATETIME(6) NOT NULL,
            revoked_at DATETIME(6) NULL,
            INDEX flownative_oauth2_server_access_token_by_grant (grant_id),
            CONSTRAINT flownative_oauth2_server_access_token_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES flownative_oauth2_server_grant (grant_id) ON DELETE CASCADE
        ) ' . self::TABLE_OPTIONS);

        $this->addSql('CREATE TABLE flownative_oauth2_server_refresh_token (
            token_digest VARCHAR(64) NOT NULL PRIMARY KEY,
            grant_id CHAR(36) NOT NULL,
            access_token_digest VARCHAR(64) NOT NULL,
            created_at DATETIME(6) NOT NULL,
            expires_at DATETIME(6) NOT NULL,
            spent_at DATETIME(6) NULL,
            revoked_at DATETIME(6) NULL,
            INDEX flownative_oauth2_server_refresh_token_by_grant (grant_id),
            CONSTRAINT flownative_oauth2_server_refresh_token_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES flownative_oauth2_server_grant (grant_id) ON DELETE CASCADE
        ) ' . self::TABLE_OPTIONS);
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!($this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform), 'Migration can only be executed safely on "mysql".');

        $this->addSql('DROP TABLE flownative_oauth2_server_refresh_token');
        $this->addSql('DROP TABLE flownative_oauth2_server_access_token');
        $this->addSql('DROP TABLE flownative_oauth2_server_authorization_code');
        $this->addSql('DROP TABLE flownative_oauth2_server_grant');
        $this->addSql('DROP TABLE flownative_oauth2_server_authorization_request');
        $this->addSql('DROP TABLE flownative_oauth2_server_client');
    }
}
