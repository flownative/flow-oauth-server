<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\DatabasePlatform;
use Flownative\OAuth2\Server\TokenSecret;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use LogicException;
use Neos\Flow\Annotations as Flow;
use RuntimeException;
use SensitiveParameter;

/**
 * Access tokens by digest. League's user identifier of a token is the grant
 * it belongs to; the token takes its resource from that grant.
 */
#[Flow\Scope('singleton')]
class DbalAccessTokenRepository implements AccessTokenRepositoryInterface
{
    #[Flow\InjectConfiguration(path: 'tokenPrefixes.accessToken')]
    protected string $prefix;

    public function __construct(
        private readonly Connection $connection,
    ) {
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?string $userIdentifier = null): AccessTokenEntityInterface
    {
        if ($userIdentifier === null || $userIdentifier === '') {
            throw new LogicException('An access token is only issued under a grant', 1795083641);
        }
        $accessToken = new AccessToken($this->prefix);
        $accessToken->setClient($clientEntity);
        $accessToken->setUserIdentifier($userIdentifier);
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }
        return $accessToken;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        if (!$accessTokenEntity instanceof AccessToken) {
            throw new LogicException('Only opaque access tokens are persisted', 1795083642);
        }
        $platform = DatabasePlatform::of($this->connection);
        $inserted = $this->connection->executeStatement(
            "INSERT INTO flownative_oauth2_server_access_token (token_digest, grant_id, resource, scopes, created_at, expires_at)
             SELECT :digest, g.grant_id, g.resource, :scopes, {$platform->now()}, :expiresAt
             FROM flownative_oauth2_server_grant g
             WHERE g.grant_id = :grantId AND g.revoked_at IS NULL",
            [
                'digest' => $accessTokenEntity->digest(),
                'grantId' => $accessTokenEntity->getUserIdentifier(),
                'scopes' => json_encode(array_map(static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(), $accessTokenEntity->getScopes()), JSON_THROW_ON_ERROR),
                'expiresAt' => $platform->timestamp($accessTokenEntity->getExpiryDateTime()),
            ]
        );
        if ($inserted !== 1) {
            throw new RuntimeException('The grant of a new access token is gone or revoked', 1795083643);
        }
    }

    public function revokeAccessToken(#[SensitiveParameter] string $tokenId): void
    {
        $this->revokeByDigest(TokenSecret::digest($this->prefix . $tokenId));
    }

    public function revokeByDigest(string $digest): void
    {
        $now = DatabasePlatform::of($this->connection)->now();
        $this->connection->executeStatement(
            "UPDATE flownative_oauth2_server_access_token SET revoked_at = {$now} WHERE token_digest = :digest AND revoked_at IS NULL",
            ['digest' => $digest]
        );
    }

    public function isAccessTokenRevoked(#[SensitiveParameter] string $tokenId): bool
    {
        $platform = DatabasePlatform::of($this->connection);
        return $this->connection->fetchOne(
            'SELECT 1 FROM flownative_oauth2_server_access_token t
             JOIN flownative_oauth2_server_grant g ON g.grant_id = t.grant_id
             WHERE t.token_digest = :digest AND t.revoked_at IS NULL AND g.revoked_at IS NULL
               AND (g.expires_at IS NULL OR g.expires_at > ' . $platform->now() . ')',
            ['digest' => TokenSecret::digest($this->prefix . $tokenId)]
        ) === false;
    }
}
