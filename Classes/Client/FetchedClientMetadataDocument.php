<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Client;

use Flownative\OAuth2\Server\League\Client;
use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final readonly class FetchedClientMetadataDocument
{
    public function __construct(
        public Client $client,
        public int $cacheLifetime, # seconds
    ) {
    }
}
