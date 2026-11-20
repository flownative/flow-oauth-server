<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final readonly class ValidatedAuthorizationRequest
{
    /**
     * @param list<string> $scopes
     */
    public function __construct(
        public Client $client,
        public string $redirectUri,
        public ?string $state,
        public array $scopes,
        public string $codeChallenge,
        public string $resource,
    ) {
    }
}
