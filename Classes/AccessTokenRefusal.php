<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use Neos\Flow\Annotations as Flow;

/**
 * A refused bearer token with the grant and client it belongs to, where it is known at all.
 */
#[Flow\Proxy(false)]
final readonly class AccessTokenRefusal
{
    public function __construct(
        public AccessTokenRefusalReason $reason,
        public ?string $grantIdentifier,
        public ?string $clientIdentifier,
    ) {
    }
}
