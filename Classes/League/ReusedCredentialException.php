<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use League\OAuth2\Server\Exception\OAuthServerException;

/**
 * A code or refresh token presented a second time. It answers invalid_grant
 * like any dead credential; the token endpoint revokes the grant after the
 * transaction rolled back, as a second use is how a stolen one shows.
 */
final class ReusedCredentialException extends OAuthServerException
{
    private string $grantIdentifier = '';

    public static function ofGrant(string $grantIdentifier): self
    {
        $exception = new self('The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.', 10, 'invalid_grant', 400, 'The credential was used before');
        $exception->grantIdentifier = $grantIdentifier;
        return $exception;
    }

    public function grantIdentifier(): string
    {
        return $this->grantIdentifier;
    }
}
