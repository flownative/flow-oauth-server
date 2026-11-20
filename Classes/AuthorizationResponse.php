<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final readonly class AuthorizationResponse
{
    public function __construct(
        public string $grantIdentifier,
        public string $redirectUri, # carries code, state and iss
    ) {
    }
}
