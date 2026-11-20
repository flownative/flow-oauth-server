<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Takes the issuer from the host of an https request, so that the request
 * must reach the application with its public host and scheme. A request
 * over plain http names no issuer.
 */
final class RequestHostIssuerResolver implements IssuerResolverInterface
{
    public function issuerFor(ServerRequestInterface $request): Issuer
    {
        $uri = $request->getUri();
        if ($uri->getScheme() !== 'https') {
            throw new UnknownIssuerException('Only a request over https names the issuer', 1795160002);
        }
        $port = $uri->getPort();
        try {
            return Issuer::fromString($uri->getScheme() . '://' . $uri->getHost() . ($port !== null ? ':' . $port : ''));
        } catch (InvalidArgumentException $exception) {
            throw new UnknownIssuerException('The request names no host to be the issuer', 1795083640, $exception);
        }
    }
}
