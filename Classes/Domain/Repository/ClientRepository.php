<?php

namespace Flownative\OAuth2\Server\Domain\Repository;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Neos\Flow\Annotations\Scope;
use Neos\Flow\Persistence\Repository;

/**
 * @Scope("singleton")
 */
class ClientRepository extends Repository implements ClientRepositoryInterface
{
    public function getClientEntity($clientIdentifier, $grantType, $clientSecret = null, $mustValidateSecret = true)
    {
        // TODO: Implement getClientEntity() method.
    }
}
