<?php

namespace Flownative\OAuth2\Server\Domain\Repository;

use Flownative\OAuth2\Server\Domain\Model\ServerConfiguration;
use Neos\Flow\Annotations\Scope;
use Neos\Flow\Persistence\Repository;

/**
 * @Scope("singleton")
 */
class ServerConfigurationRepository extends Repository
{
    /**
     * @param string $key
     * @return ServerConfiguration|null
     */
    public function findOneByKey(string $key): ?ServerConfiguration
    {
        return $this->__call('findOneByKey', [$key]);
    }
}
