<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\TokenSecret;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use LogicException;
use Neos\Flow\Annotations as Flow;
use RuntimeException;

/**
 * Refresh tokens by digest, each spent once by a conditional UPDATE.
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
        $inserted = $this->connection->executeStatement(
            'INSERT INTO flownative_oauth2_server_refresh_token (token_digest, grant_id, access_token_digest, created_at, expires_at)
             SELECT :digest, g.grant_id, :accessTokenDigest, now(), :expiresAt
             FROM flownative_oauth2_server_grant g
             WHERE g.grant_id = :grantId AND g.revoked_at IS NULL',
            [
                'digest' => $refreshTokenEntity->digest(),
                'grantId' => $accessToken->getUserIdentifier(),
                'accessTokenDigest' => $accessToken->digest(),
                'expiresAt' => $refreshTokenEntity->getExpiryDateTime()->format(DATE_ATOM),
            ]
        );
        if ($inserted !== 1) {
            throw new RuntimeException('The grant of a new refresh token is gone or revoked', 1795083645);
        }
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $this->connection->executeStatement(
            'UPDATE flownative_oauth2_server_refresh_token SET revoked_at = now() WHERE token_digest = :digest AND revoked_at IS NULL',
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
        return $this->connection->fetchOne(
            'SELECT 1 FROM flownative_oauth2_server_refresh_token
             WHERE token_digest = :digest AND spent_at > now() - make_interval(secs => :seconds)',
            ['digest' => TokenSecret::digest($secret), 'seconds' => $seconds]
        ) !== false;
    }
}
