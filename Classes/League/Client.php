<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use Neos\Flow\Annotations as Flow;

/**
 * Every client is public: it proves nothing but its code verifier.
 */
#[Flow\Proxy(false)]
final readonly class Client implements ClientEntityInterface
{
    /**
     * @param non-empty-string $identifier
     * @param list<string> $redirectUris
     */
    public function __construct(
        public string $identifier,
        public string $name,
        public array $redirectUris,
    ) {
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @return list<string>
     */
    public function getRedirectUri(): array
    {
        return $this->redirectUris;
    }

    public function isConfidential(): bool
    {
        return false;
    }

    public function supportsGrantType(string $grantType): bool
    {
        return in_array($grantType, ['authorization_code', 'refresh_token'], true);
    }
}
