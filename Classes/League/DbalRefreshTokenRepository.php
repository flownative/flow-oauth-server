<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\DatabasePlatform;
use Flownative\OAuth2\Server\TokenSecret;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use LogicException;
use Neos\Flow\Annotations as Flow;
use RuntimeException;

/**
 * Refresh tokens by digest, each spent once under a lock of its grant.
 */
#[Flow\Scope('singleton')]
class DbalRefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    #[Flow\InjectConfiguration(path: 'tokenPrefixes.refreshToken')]
    protected string $prefix;

    public function __construct(
        private readonly Connection $connection,
    ) {
    }

    public function getNewRefreshToken(): RefreshTokenEntityInterface
    {
        return new RefreshToken($this->prefix);
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $accessToken = $refreshTokenEntity->getAccessToken();
        if (!$refreshTokenEntity instanceof RefreshToken || !$accessToken instanceof AccessToken) {
            throw new LogicException('Only opaque refresh tokens are persisted', 1795083644);
        }
        $platform = DatabasePlatform::of($this->connection);
        $inserted = $this->connection->executeStatement(
            "INSERT INTO flownative_oauth2_server_refresh_token (token_digest, grant_id, access_token_digest, created_at, expires_at)
             SELECT :digest, g.grant_id, :accessTokenDigest, {$platform->now()}, :expiresAt
             FROM flownative_oauth2_server_grant g
             WHERE g.grant_id = :grantId AND g.revoked_at IS NULL",
            [
                'digest' => $refreshTokenEntity->digest(),
                'grantId' => $accessToken->getUserIdentifier(),
                'accessTokenDigest' => $accessToken->digest(),
                'expiresAt' => $platform->timestamp($refreshTokenEntity->getExpiryDateTime()),
            ]
        );
        if ($inserted !== 1) {
            throw new RuntimeException('The grant of a new refresh token is gone or revoked', 1795083645);
        }
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $now = DatabasePlatform::of($this->connection)->now();
        $this->connection->executeStatement(
            "UPDATE flownative_oauth2_server_refresh_token SET revoked_at = {$now} WHERE token_digest = :digest AND revoked_at IS NULL",
            ['digest' => TokenSecret::digest($this->prefix . $tokenId)]
        );
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        return $this->connection->fetchOne(
            'SELECT 1 FROM flownative_oauth2_server_refresh_token t
             JOIN flownative_oauth2_server_grant g ON g.grant_id = t.grant_id
             WHERE t.token_digest = :digest AND t.spent_at IS NULL AND t.revoked_at IS NULL AND g.revoked_at IS NULL',
            ['digest' => TokenSecret::digest($this->prefix . $tokenId)]
        ) === false;
    }

    /**
     * Marks the token spent if it is still good and returns what it was issued
     * under, or null; a concurrent second spend waits for the row and finds it
     * spent. The grant row is locked first, in the order revoking takes.
     */
    public function spend(string $secret): ?SpentRefreshToken
    {
        $digest = TokenSecret::digest($secret);
        if (DatabasePlatform::of($this->connection) === DatabasePlatform::MYSQL) {
            return $this->spendOnMysql($digest);
        }
        $this->connection->executeQuery(
            'SELECT g.grant_id FROM flownative_oauth2_server_grant g
             JOIN flownative_oauth2_server_refresh_token t ON t.grant_id = g.grant_id
             WHERE t.token_digest = :digest FOR UPDATE OF g',
            ['digest' => $digest]
        );
        $row = $this->connection->fetchAssociative(
            'UPDATE flownative_oauth2_server_refresh_token t SET spent_at = now()
             FROM flownative_oauth2_server_grant g
             WHERE t.token_digest = :digest AND g.grant_id = t.grant_id
               AND t.spent_at IS NULL AND t.revoked_at IS NULL AND t.expires_at > now() AND g.revoked_at IS NULL
             RETURNING t.grant_id, t.access_token_digest, g.client_id, g.resource, g.scopes',
            ['digest' => $digest]
        );
        return $row === false ? null : SpentRefreshToken::fromRow($row);
    }

    /**
     * A token that was spent before: presented again, it is the sign of a stolen one.
     */
    public function spentBefore(string $secret): ?SpentRefreshToken
    {
        $row = $this->connection->fetchAssociative(
            'SELECT t.grant_id, t.access_token_digest, g.client_id, g.resource, g.scopes
             FROM flownative_oauth2_server_refresh_token t
             JOIN flownative_oauth2_server_grant g ON g.grant_id = t.grant_id
             WHERE t.token_digest = :digest AND t.spent_at IS NOT NULL',
            ['digest' => TokenSecret::digest($secret)]
        );
        return $row === false ? null : SpentRefreshToken::fromRow($row);
    }

    public function wasSpentWithin(string $secret, int $seconds): bool
    {
        if (DatabasePlatform::of($this->connection) === DatabasePlatform::MYSQL) {
            return $this->connection->fetchOne(
                'SELECT 1 FROM flownative_oauth2_server_refresh_token WHERE token_digest = :digest AND spent_at > :spentAfter',
                ['digest' => TokenSecret::digest($secret), 'spentAfter' => DatabasePlatform::MYSQL->timestamp(new DateTimeImmutable(sprintf('-%d seconds', $seconds)))]
            ) !== false;
        }
        return $this->connection->fetchOne(
            'SELECT 1 FROM flownative_oauth2_server_refresh_token
             WHERE token_digest = :digest AND spent_at > now() - make_interval(secs => :seconds)',
            ['digest' => TokenSecret::digest($secret), 'seconds' => $seconds]
        ) !== false;
    }

    /**
     * MySQL has no UPDATE … RETURNING, so the token row is locked and read
     * before it is marked spent, in a transaction of its own or nested in the
     * caller's. A concurrent second spend waits for the lock and then finds
     * the token spent. The grant is read without a lock first, because a
     * locking join would take the rows in an order of the optimizer's choice.
     */
    private function spendOnMysql(string $digest): ?SpentRefreshToken
    {
        return $this->connection->transactional(static function (Connection $connection) use ($digest): ?SpentRefreshToken {
            $grantIdentifier = $connection->fetchOne('SELECT grant_id FROM flownative_oauth2_server_refresh_token WHERE token_digest = :digest', ['digest' => $digest]);
            if (!is_string($grantIdentifier)) {
                return null;
            }
            $connection->fetchOne('SELECT grant_id FROM flownative_oauth2_server_grant WHERE grant_id = :grantId FOR UPDATE', ['grantId' => $grantIdentifier]);
            $row = $connection->fetchAssociative(
                'SELECT t.grant_id, t.access_token_digest, g.client_id, g.resource, g.scopes
                 FROM flownative_oauth2_server_refresh_token t
                 JOIN flownative_oauth2_server_grant g ON g.grant_id = t.grant_id
                 WHERE t.token_digest = :digest AND t.spent_at IS NULL AND t.revoked_at IS NULL AND t.expires_at > UTC_TIMESTAMP(6) AND g.revoked_at IS NULL
                 FOR UPDATE',
                ['digest' => $digest]
            );
            if ($row === false) {
                return null;
            }
            $connection->executeStatement('UPDATE flownative_oauth2_server_refresh_token SET spent_at = UTC_TIMESTAMP(6) WHERE token_digest = :digest', ['digest' => $digest]);
            return SpentRefreshToken::fromRow($row);
        });
    }
}
