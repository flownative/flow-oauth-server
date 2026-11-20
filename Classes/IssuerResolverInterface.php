<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Which issuer a request reaches. An application serving several hosts
 * replaces the default to refuse hosts it does not serve.
 */
interface IssuerResolverInterface
{
    /**
     * @throws UnknownIssuerException
     */
    public function issuerFor(ServerRequestInterface $request): Issuer;
}
