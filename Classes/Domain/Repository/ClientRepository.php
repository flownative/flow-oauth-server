<?php

namespace Flownative\OAuth2\Server\Domain\Repository;

use Flownative\OAuth2\Server\Domain\Model\Client;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Neos\Flow\Annotations\Scope;
use Neos\Flow\Annotations\Inject;
use Neos\Flow\Log\SystemLoggerInterface;
use Neos\Flow\Persistence\Repository;

/**
 * @Scope("singleton")
 */
class ClientRepository extends Repository implements ClientRepositoryInterface
{
    /**
     * @Inject
     * @var SystemLoggerInterface
     */
    protected $logger;

    /**
     * @param string $identifier
     * @return Client|null
     */
    public function findOneByIdentifier(string $identifier): ?Client
    {
        return $this->__call('findOneByIdentifier', [$identifier]);
    }

    /**
     * @param string $clientIdentifier
     * @param string $grantType
     * @param null $clientSecret
     * @param bool $mustValidateSecret
     * @return ClientEntityInterface|null
     */
    public function getClientEntity($clientIdentifier, $grantType, $clientSecret = null, $mustValidateSecret = true): ?ClientEntityInterface
    {
        $client = $this->findOneByIdentifier($clientIdentifier);
        if ($client === null) {
            return null;
        }
        if ($client->getGrantType() !== $grantType) {
            return null;
        }
        if ($mustValidateSecret && !$client->validateSecret($clientSecret)) {
            $this->logger->log(sprintf('Incorrect secret provided for client %s (grant type %s).', $clientIdentifier, $grantType), LOG_INFO);
            return null;
        }
        return $client;
    }
}
