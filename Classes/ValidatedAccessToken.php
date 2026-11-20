<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final readonly class ValidatedAccessToken
{
    /**
     * @param list<string> $scopes
     */
    public function __construct(
        public string $grantIdentifier,
        public string $subject,
        public string $clientIdentifier,
        public array $scopes,
    ) {
    }
}
