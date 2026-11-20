<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use Psr\Http\Message\ResponseInterface;

/**
 * Where the application asks the subject. The authorization endpoint sends a
 * validated request there; the page answers with approve() or deny() of
 * AuthorizationRequests. A request refused before its redirect URI is proved
 * is shown by the application too, never sent back to the client.
 */
interface ConsentPageInterface
{
    public function uriFor(PendingAuthorizationRequest $request): string;

    public function refusal(string $error, string $description): ResponseInterface;
}
