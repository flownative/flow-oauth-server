<?php

namespace Flownative\OAuth2\Server\Domain\Repository;

use Neos\Flow\Annotations as Flow;
use Flownative\OAuth2\Server\Domain\Model\Scope;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Neos\Flow\Persistence\Repository;

/**
 * @Flow\Scope("singleton")
 */
final class ScopeRepository extends Repository implements ScopeRepositoryInterface
{
    /**
     * @var array
     */
    private $scopes = [
        'customerAccounts-rw' => null
    ];

    /**
     * @param string $identifier
     * @return Scope|null
     */
    public function getScopeEntityByIdentifier($identifier): ?Scope
    {
        if (!key_exists($identifier, $this->scopes)) {
            return null;
        }

        if ($this->scopes[$identifier] === null) {
            $this->scopes[$identifier] = new Scope($identifier);
        }
        return $this->scopes[$identifier];
    }

    /**
     * @param array $scopes
     * @param string $grantType
     * @param ClientEntityInterface $clientEntity
     * @param null $userIdentifier
     * @return array|\League\OAuth2\Server\Entities\ScopeEntityInterface[]
     */
    public function finalizeScopes(
        array $scopes,
        $grantType,
        ClientEntityInterface $clientEntity,
        $userIdentifier = null
    ) {
        return $scopes;
    }
}
