<?php

namespace Flownative\OAuth2\Server\Domain\Repository;

use Flownative\OAuth2\Server\Domain\Model\AccessToken;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Neos\Flow\Annotations\Scope;
use Neos\Flow\Persistence\Repository;

/**
 * @Scope("singleton")
 */
class AccessTokenRepository extends Repository implements AccessTokenRepositoryInterface
{
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null)
    {
        return new AccessToken();
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
    }

    public function revokeAccessToken($tokenId)
    {
    }

    public function isAccessTokenRevoked($tokenId)
    {
        return false;
    }
}
