<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use DateInterval;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\DatabasePlatform;
use Flownative\OAuth2\Server\TokenSecret;
use Neos\Flow\Annotations as Flow;

/**
 * Authorization codes by digest, each spent once under a lock of its grant.
 * They replace league's encrypted codes, so that the database alone decides
 * whether a code is good.
 */
#[Flow\Scope('singleton')]
class AuthorizationCodes
{
    #[Flow\InjectConfiguration(path: 'lifetimes.authorizationCode')]
    protected string $lifetime;

    public function __construct(
        private readonly Connection $connection,
    ) {
    }

    /**
     * @return string the code to hand to the client
     */
    public function issue(string $grantIdentifier, string $redirectUri, string $codeChallenge): string
    {
        $code = TokenSecret::generate();
        $platform = DatabasePlatform::of($this->connection);
        $this->connection->executeStatement(
            "INSERT INTO flownative_oauth2_server_authorization_code (code_digest, grant_id, redirect_uri, code_challenge, created_at, expires_at)
             VALUES (:digest, :grantId, :redirectUri, :codeChallenge, {$platform->now()}, :expiresAt)",
            [
                'digest' => TokenSecret::digest($code),
                'grantId' => $grantIdentifier,
                'redirectUri' => $redirectUri,
                'codeChallenge' => $codeChallenge,
                'expiresAt' => $platform->timestamp((new DateTimeImmutable())->add(new DateInterval($this->lifetime))),
            ]
        );
        return $code;
    }

    /**
     * The grant row is locked first, in the order revoking takes.
     */
    public function spend(string $code): ?SpentAuthorizationCode
    {
        $digest = TokenSecret::digest($code);
        if (DatabasePlatform::of($this->connection) === DatabasePlatform::MYSQL) {
            return $this->spendOnMysql($digest);
        }
        $this->connection->executeQuery(
            'SELECT g.grant_id FROM flownative_oauth2_server_grant g
             JOIN flownative_oauth2_server_authorization_code c ON c.grant_id = g.grant_id
             WHERE c.code_digest = :digest FOR UPDATE OF g',
            ['digest' => $digest]
        );
        $row = $this->connection->fetchAssociative(
            'UPDATE flownative_oauth2_server_authorization_code c SET spent_at = now()
             FROM flownative_oauth2_server_grant g
             WHERE c.code_digest = :digest AND g.grant_id = c.grant_id
               AND c.spent_at IS NULL AND c.expires_at > now() AND g.revoked_at IS NULL
             RETURNING c.grant_id, c.redirect_uri, c.code_challenge, g.client_id, g.resource, g.scopes',
            ['digest' => $digest]
        );
        return $row === false ? null : SpentAuthorizationCode::fromRow($row);
    }

    /**
     * A code that was spent before, so that a second use by its client can revoke its tokens.
     */
    public function spentBefore(string $code): ?SpentAuthorizationCode
    {
        $row = $this->connection->fetchAssociative(
            'SELECT c.grant_id, c.redirect_uri, c.code_challenge, g.client_id, g.resource, g.scopes
             FROM flownative_oauth2_server_authorization_code c
             JOIN flownative_oauth2_server_grant g ON g.grant_id = c.grant_id
             WHERE c.code_digest = :digest AND c.spent_at IS NOT NULL',
            ['digest' => TokenSecret::digest($code)]
        );
        return $row === false ? null : SpentAuthorizationCode::fromRow($row);
    }

    /**
     * MySQL has no UPDATE … RETURNING, so the code row is locked and read
     * before it is marked spent, in a transaction of its own or nested in the
     * caller's. A concurrent second spend waits for the lock and then finds
     * the code spent. The grant is read without a lock first, because a
     * locking join would take the rows in an order of the optimizer's choice.
     */
    private function spendOnMysql(string $digest): ?SpentAuthorizationCode
    {
        return $this->connection->transactional(static function (Connection $connection) use ($digest): ?SpentAuthorizationCode {
            $grantIdentifier = $connection->fetchOne('SELECT grant_id FROM flownative_oauth2_server_authorization_code WHERE code_digest = :digest', ['digest' => $digest]);
            if (!is_string($grantIdentifier)) {
                return null;
            }
            $connection->fetchOne('SELECT grant_id FROM flownative_oauth2_server_grant WHERE grant_id = :grantId FOR UPDATE', ['grantId' => $grantIdentifier]);
            $row = $connection->fetchAssociative(
                'SELECT c.grant_id, c.redirect_uri, c.code_challenge, g.client_id, g.resource, g.scopes
                 FROM flownative_oauth2_server_authorization_code c
                 JOIN flownative_oauth2_server_grant g ON g.grant_id = c.grant_id
                 WHERE c.code_digest = :digest AND c.spent_at IS NULL AND c.expires_at > UTC_TIMESTAMP(6) AND g.revoked_at IS NULL
                 FOR UPDATE',
                ['digest' => $digest]
            );
            if ($row === false) {
                return null;
            }
            $connection->executeStatement('UPDATE flownative_oauth2_server_authorization_code SET spent_at = UTC_TIMESTAMP(6) WHERE code_digest = :digest', ['digest' => $digest]);
            return SpentAuthorizationCode::fromRow($row);
        });
    }
}
