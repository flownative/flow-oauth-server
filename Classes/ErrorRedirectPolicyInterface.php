<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

/**
 * Decides whether a refused authorization request goes back to the client's
 * proved redirect URI. Anybody can register a client with any redirect URI,
 * so a redirect for an unknown client would be an open redirect; a request
 * that may not go back is shown as a refusal by the consent page.
 */
interface ErrorRedirectPolicyInterface
{
    public function mayRedirectErrors(Issuer $issuer, string $clientIdentifier): bool;
}
