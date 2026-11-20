<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use Neos\Flow\Annotations as Flow;

#[Flow\Scope('singleton')]
final class UnthrottledClientMetadataFetches implements ClientMetadataFetchThrottleInterface
{
    public function allowsFetch(string $sourceAddress): bool
    {
        return true;
    }
}
