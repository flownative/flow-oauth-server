<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Neos\Flow\Annotations as Flow;

/**
 * The scopes of the settings. They name the audience only; what a client may
 * do is the application's to decide from the grant.
 */
#[Flow\Scope('singleton')]
class ConfiguredScopeRepository implements ScopeRepositoryInterface
{
    /**
     * @var list<string>
     */
    #[Flow\InjectConfiguration(path: 'scopes.supported')]
    protected array $supportedScopes;

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return $identifier !== '' && in_array($identifier, $this->supportedScopes, true) ? new Scope($identifier) : null;
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     * @return ScopeEntityInterface[]
     */
    public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity, ?string $userIdentifier = null, ?string $authCodeId = null): array
    {
        return $scopes;
    }
}
