<?php

declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The tables of the authorization server: clients, stored authorization
 * requests, grants and the codes and tokens issued under them. Codes and
 * tokens are kept as SHA-256 digests only.
 */
final class Version20261119101252 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Create the tables of the OAuth 2 authorization server';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(!($this->connection->getDatabasePlatform() instanceof PostgreSQLPlatform));

        $this->addSql("CREATE TABLE flownative_oauth2_server_client (
            client_id text PRIMARY KEY,
            client_name text NOT NULL,
            redirect_uris jsonb NOT NULL,
            origin text NOT NULL CHECK (origin IN ('registration', 'metadata_document')),
            registered_from text NULL,
            created_at timestamptz NOT NULL,
            expires_at timestamptz NULL
        )");

        $this->addSql('CREATE TABLE flownative_oauth2_server_authorization_request (
            request_id text PRIMARY KEY,
            issuer text NOT NULL,
            client_id text NOT NULL,
            client_name text NOT NULL,
            redirect_uri text NOT NULL,
            state text NULL,
            scopes jsonb NOT NULL,
            code_challenge text NOT NULL,
            resource text NOT NULL,
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL
        )');

        $this->addSql('CREATE TABLE flownative_oauth2_server_grant (
            grant_id uuid PRIMARY KEY,
            subject text NOT NULL,
            client_id text NOT NULL,
            client_name text NOT NULL,
            redirect_uri text NOT NULL,
            issuer text NOT NULL,
            resource text NOT NULL,
            scopes jsonb NOT NULL,
            created_at timestamptz NOT NULL,
            last_used_at timestamptz NULL,
            revoked_at timestamptz NULL
        )');
        $this->addSql('CREATE INDEX flownative_oauth2_server_grant_by_subject ON flownative_oauth2_server_grant (subject)');
        $this->addSql('CREATE INDEX flownative_oauth2_server_grant_by_client ON flownative_oauth2_server_grant (client_id)');

        $this->addSql('CREATE TABLE flownative_oauth2_server_authorization_code (
            code_digest text PRIMARY KEY,
            grant_id uuid NOT NULL REFERENCES flownative_oauth2_server_grant (grant_id) ON DELETE CASCADE,
            redirect_uri text NOT NULL,
            code_challenge text NOT NULL,
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL,
            spent_at timestamptz NULL
        )');
        $this->addSql('CREATE INDEX flownative_oauth2_server_authorization_code_by_grant ON flownative_oauth2_server_authorization_code (grant_id)');

        $this->addSql('CREATE TABLE flownative_oauth2_server_access_token (
            token_digest text PRIMARY KEY,
            grant_id uuid NOT NULL REFERENCES flownative_oauth2_server_grant (grant_id) ON DELETE CASCADE,
            resource text NOT NULL,
            scopes jsonb NOT NULL,
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL,
            revoked_at timestamptz NULL
        )');
        $this->addSql('CREATE INDEX flownative_oauth2_server_access_token_by_grant ON flownative_oauth2_server_access_token (grant_id)');

        $this->addSql('CREATE TABLE flownative_oauth2_server_refresh_token (
            token_digest text PRIMARY KEY,
            grant_id uuid NOT NULL REFERENCES flownative_oauth2_server_grant (grant_id) ON DELETE CASCADE,
            access_token_digest text NOT NULL,
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL,
            spent_at timestamptz NULL,
            revoked_at timestamptz NULL
        )');
        $this->addSql('CREATE INDEX flownative_oauth2_server_refresh_token_by_grant ON flownative_oauth2_server_refresh_token (grant_id)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!($this->connection->getDatabasePlatform() instanceof PostgreSQLPlatform));

        $this->addSql('DROP TABLE flownative_oauth2_server_refresh_token');
        $this->addSql('DROP TABLE flownative_oauth2_server_access_token');
        $this->addSql('DROP TABLE flownative_oauth2_server_authorization_code');
        $this->addSql('DROP TABLE flownative_oauth2_server_grant');
        $this->addSql('DROP TABLE flownative_oauth2_server_authorization_request');
        $this->addSql('DROP TABLE flownative_oauth2_server_client');
    }
}
