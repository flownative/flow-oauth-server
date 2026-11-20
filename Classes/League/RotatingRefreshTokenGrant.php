<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use DateInterval;
use Flownative\OAuth2\Server\Grants;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Neos\Flow\Log\Utility\LogEnvironment;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

/**
 * The refresh token grant. Client, grant and scopes come from the stored row,
 * never from the request; the old refresh token is spent and its access token
 * revoked in the transaction that issues the new pair.
 */
final class RotatingRefreshTokenGrant extends AbstractGrant
{
    public function __construct(
        private readonly DbalRefreshTokenRepository $refreshTokens,
        private readonly DbalAccessTokenRepository $accessTokens,
        private readonly Grants $grants,
        private readonly string $resource,
        private readonly int $retryGracePeriod, # seconds
        private readonly ?LoggerInterface $logger,
    ) {
        $this->setRefreshTokenRepository($refreshTokens);
    }

    public function getIdentifier(): string
    {
        return 'refresh_token';
    }

    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseTypeInterface $responseType, DateInterval $accessTokenTTL): ResponseTypeInterface
    {
        $client = $this->validateClient($request);
        $secret = $this->getRequestParameter('refresh_token', $request);
        if ($secret === null) {
            throw OAuthServerException::invalidRequest('refresh_token');
        }

        $spentToken = $this->refreshTokens->spend($secret);
        if ($spentToken === null) {
            $earlierToken = $this->refreshTokens->spentBefore($secret);
            // Another client presenting the token proves nothing.
            if ($earlierToken === null || $earlierToken->clientIdentifier !== $client->getIdentifier()) {
                throw OAuthServerException::invalidGrant();
            }
            if ($this->refreshTokens->wasSpentWithin($secret, $this->retryGracePeriod)) {
                // Most likely a retry after a lost answer, but a thief who refreshed first looks the same.
                $this->logger?->warning(sprintf('Client %s presented a spent refresh token of grant %s again within the retry grace period; the grant stays', $client->getIdentifier(), $earlierToken->grantIdentifier), LogEnvironment::fromMethodName(__METHOD__));
                throw OAuthServerException::invalidGrant();
            }
            throw ReusedCredentialException::ofGrant($earlierToken->grantIdentifier);
        }
        if ($spentToken->clientIdentifier !== $client->getIdentifier()) {
            throw OAuthServerException::invalidGrant();
        }
        if ($spentToken->resource !== $this->resource || $this->getRequestParameter('resource', $request, $this->resource) !== $this->resource) {
            throw OAuthServerException::invalidGrant('The refresh token was issued for another resource');
        }

        $scopes = $spentToken->scopes;
        $requestedScope = $this->getRequestParameter('scope', $request);
        if ($requestedScope !== null) {
            $scopes = Scope::identifiersOf($this->validateScopes($requestedScope));
            foreach ($scopes as $scope) {
                if (!in_array($scope, $spentToken->scopes, true)) {
                    throw OAuthServerException::invalidScope($scope);
                }
            }
        }

        $this->accessTokens->revokeByDigest($spentToken->accessTokenDigest);
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $spentToken->grantIdentifier, Scope::listOf($scopes));
        $responseType->setAccessToken($accessToken);
        $refreshToken = $this->issueRefreshToken($accessToken);
        if ($refreshToken !== null) {
            $responseType->setRefreshToken($refreshToken);
        }
        $this->grants->touch($spentToken->grantIdentifier);

        return $responseType;
    }
}
