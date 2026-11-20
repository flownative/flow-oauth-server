<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;
use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final class Scope implements ScopeEntityInterface
{
    use ScopeTrait;

    /**
     * @param non-empty-string $identifier
     */
    public function __construct(
        private readonly string $identifier,
    ) {
    }

    /**
     * @param list<string> $identifiers
     * @return list<self>
     */
    public static function listOf(array $identifiers): array
    {
        return array_values(array_map(static fn (string $identifier): self => new self($identifier), array_filter($identifiers, static fn (string $identifier): bool => $identifier !== '')));
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     * @return list<string>
     */
    public static function identifiersOf(array $scopes): array
    {
        return array_values(array_map(static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(), $scopes));
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }
}
