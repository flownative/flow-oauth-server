<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

/**
 * Asked before the server fetches a client metadata document for a request,
 * so that the application can bound how many fetches one source address
 * causes. Counting and the budget are the application's.
 */
interface ClientMetadataFetchThrottleInterface
{
    public function allowsFetch(string $sourceAddress): bool;
}
