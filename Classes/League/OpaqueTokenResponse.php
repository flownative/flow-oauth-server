<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use LogicException;
use Psr\Http\Message\ResponseInterface;

/**
 * The token answer with both tokens as opaque secrets, where league's would
 * encrypt the refresh token's payload into it.
 */
final class OpaqueTokenResponse extends AbstractResponseType
{
    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        $parameters = [
            'token_type' => 'Bearer',
            'expires_in' => $this->accessToken->getExpiryDateTime()->getTimestamp() - time(),
            'access_token' => $this->accessToken->toString(),
            'scope' => implode(' ', Scope::identifiersOf($this->accessToken->getScopes())),
        ];
        if (isset($this->refreshToken)) {
            if (!$this->refreshToken instanceof RefreshToken) {
                throw new LogicException('Only opaque refresh tokens are handed out', 1795083657);
            }
            $parameters['refresh_token'] = $this->refreshToken->secret();
        }

        $response = $response
            ->withStatus(200)
            ->withHeader('Pragma', 'no-cache')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Content-Type', 'application/json; charset=UTF-8');
        $response->getBody()->write(json_encode($parameters, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        return $response;
    }
}
