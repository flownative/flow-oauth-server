<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use DateInterval;
use Flownative\OAuth2\Server\Client\RedirectUris;
use Flownative\OAuth2\Server\Grants;
use League\OAuth2\Server\CodeChallengeVerifiers\S256Verifier;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractAuthorizeGrant;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The authorization code grant with PKCE, S256 only. It replaces league's
 * grant, which takes plain and encrypted codes: here a code is a secret the
 * database spends once, inside the transaction that issues the tokens. Errors
 * carry a redirect URI only once the client and that URI are proved.
 */
final class PkceAuthorizationCodeGrant extends AbstractAuthorizeGrant
{
    private const string CODE_VERIFIER_PATTERN = '/^[A-Za-z0-9\-._~]{43,128}$/';

    public function __construct(
        private readonly AuthorizationCodes $authorizationCodes,
        private readonly Grants $grants,
        private readonly string $resource,
    ) {
    }

    public function getIdentifier(): string
    {
        return 'authorization_code';
    }

    /**
     * @throws OAuthServerException
     */
    public function validateRequest(ServerRequestInterface $request): ValidatedAuthorizationRequest
    {
        $clientIdentifier = $this->getQueryStringParameter('client_id', $request);
        if ($clientIdentifier === null) {
            throw OAuthServerException::invalidRequest('client_id');
        }
        $client = $this->getClientEntityOrFail($clientIdentifier, $request);
        if (!$client instanceof Client) {
            throw new LogicException('The client repository returned a client of another kind', 1795083656);
        }
        $redirectUri = $this->getQueryStringParameter('redirect_uri', $request);
        if ($redirectUri === null) {
            if (count($client->redirectUris) !== 1) {
                throw OAuthServerException::invalidRequest('redirect_uri', 'The client registered several redirect URIs, so the request has to name one');
            }
            $redirectUri = $client->redirectUris[0];
        } elseif (!RedirectUris::matches($redirectUri, $client->redirectUris)) {
            throw OAuthServerException::invalidRequest('redirect_uri', 'The redirect URI is not registered for this client');
        }

        if ($this->getQueryStringParameter('response_type', $request) !== 'code') {
            throw self::redirectedError('unsupported_response_type', 'The response type must be code', $redirectUri);
        }
        $codeChallenge = $this->getQueryStringParameter('code_challenge', $request);
        if ($codeChallenge === null) {
            throw self::redirectedError('invalid_request', 'A code_challenge is required', $redirectUri);
        }
        if ($this->getQueryStringParameter('code_challenge_method', $request) !== 'S256') {
            throw self::redirectedError('invalid_request', 'The code_challenge_method must be S256', $redirectUri);
        }
        if (preg_match(self::CODE_VERIFIER_PATTERN, $codeChallenge) !== 1) {
            throw self::redirectedError('invalid_request', 'The code_challenge does not follow RFC 7636', $redirectUri);
        }
        $state = $this->getQueryStringParameter('state', $request);
        $resource = $this->getQueryStringParameter('resource', $request, $this->resource);
        if ($resource !== $this->resource) {
            throw self::redirectedError('invalid_target', 'The resource is not served by this authorization server', $redirectUri);
        }
        $scopes = $this->validateScopes($this->getQueryStringParameter('scope', $request, $this->defaultScope), $redirectUri);

        return new ValidatedAuthorizationRequest(
            $client,
            $redirectUri,
            $state,
            Scope::identifiersOf($scopes),
            $codeChallenge,
            $this->resource,
        );
    }

    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseTypeInterface $responseType, DateInterval $accessTokenTTL): ResponseTypeInterface
    {
        $client = $this->validateClient($request);
        $code = $this->getRequestParameter('code', $request);
        if ($code === null) {
            throw OAuthServerException::invalidRequest('code');
        }
        $codeVerifier = $this->getRequestParameter('code_verifier', $request);
        if ($codeVerifier === null || preg_match(self::CODE_VERIFIER_PATTERN, $codeVerifier) !== 1) {
            throw OAuthServerException::invalidRequest('code_verifier', 'A code_verifier following RFC 7636 is required');
        }

        $spentCode = $this->authorizationCodes->spend($code);
        if ($spentCode === null) {
            $earlierCode = $this->authorizationCodes->spentBefore($code);
            // Only the code's own client with its verifier proves a second use, or anybody holding a spent code could revoke the grant.
            if ($earlierCode !== null && $earlierCode->clientIdentifier === $client->getIdentifier() && (new S256Verifier())->verifyCodeChallenge($codeVerifier, $earlierCode->codeChallenge)) {
                throw ReusedCredentialException::ofGrant($earlierCode->grantIdentifier);
            }
            throw OAuthServerException::invalidGrant();
        }
        if ($spentCode->clientIdentifier !== $client->getIdentifier()) {
            throw OAuthServerException::invalidGrant();
        }
        if ($spentCode->resource !== $this->resource || $this->getRequestParameter('resource', $request, $this->resource) !== $this->resource) {
            throw OAuthServerException::invalidGrant('The code was issued for another resource');
        }
        if ($this->getRequestParameter('redirect_uri', $request, $spentCode->redirectUri) !== $spentCode->redirectUri) {
            throw OAuthServerException::invalidGrant('The redirect URI differs from the one of the authorization request');
        }
        if (!(new S256Verifier())->verifyCodeChallenge($codeVerifier, $spentCode->codeChallenge)) {
            throw OAuthServerException::invalidGrant('The code_verifier does not match the code_challenge');
        }

        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $spentCode->grantIdentifier, Scope::listOf($spentCode->scopes));
        $responseType->setAccessToken($accessToken);
        $refreshToken = $this->issueRefreshToken($accessToken);
        if ($refreshToken !== null) {
            $responseType->setRefreshToken($refreshToken);
        }
        $this->grants->touch($spentCode->grantIdentifier);

        return $responseType;
    }

    private static function redirectedError(string $error, string $description, string $redirectUri): OAuthServerException
    {
        return new OAuthServerException($description, 3, $error, 400, null, $redirectUri);
    }
}
