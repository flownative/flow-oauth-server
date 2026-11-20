<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use Doctrine\DBAL\Connection;
use Neos\Flow\Annotations as Flow;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Checks the bearer token of a request to the protected resource. A token
 * counts only for the resource of the issuer the request reached, so a token
 * of one host is refused under another.
 */
#[Flow\Scope('singleton')]
class AccessTokenValidator
{
    public function __construct(
        private readonly Connection $connection,
        private readonly Endpoints $endpoints,
    ) {
    }

    public function validateRequest(ServerRequestInterface $request, Issuer $issuer): ?ValidatedAccessToken
    {
        if (preg_match('/^Bearer\s+(\S+)$/i', $request->getHeaderLine('Authorization'), $matches) !== 1) {
            return null;
        }
        return $this->validate($matches[1], $issuer);
    }

    public function validate(string $accessToken, Issuer $issuer): ?ValidatedAccessToken
    {
        $now = DatabasePlatform::of($this->connection)->now();
        $row = $this->connection->fetchAssociative(
            "SELECT t.grant_id, t.scopes, g.subject, g.client_id
             FROM flownative_oauth2_server_access_token t
             JOIN flownative_oauth2_server_grant g ON g.grant_id = t.grant_id
             WHERE t.token_digest = :digest AND t.resource = :resource
               AND t.revoked_at IS NULL AND t.expires_at > {$now} AND g.revoked_at IS NULL",
            ['digest' => TokenSecret::digest($accessToken), 'resource' => $this->endpoints->resourceOf($issuer)]
        );
        if ($row === false) {
            return null;
        }
        return new ValidatedAccessToken(
            Rows::string($row, 'grant_id'),
            Rows::string($row, 'subject'),
            Rows::string($row, 'client_id'),
            Rows::stringList($row, 'scopes'),
        );
    }

    /**
     * Why validate() refused the token; only for the log, never for the client.
     */
    public function refusalOf(string $accessToken, Issuer $issuer): AccessTokenRefusal
    {
        $now = DatabasePlatform::of($this->connection)->now();
        $row = $this->connection->fetchAssociative(
            "SELECT t.grant_id, g.client_id,
                    t.revoked_at IS NOT NULL AS token_revoked, t.expires_at <= {$now} AS expired, g.revoked_at IS NOT NULL AS grant_revoked
             FROM flownative_oauth2_server_access_token t
             JOIN flownative_oauth2_server_grant g ON g.grant_id = t.grant_id
             WHERE t.token_digest = :digest",
            ['digest' => TokenSecret::digest($accessToken)]
        );
        if ($row === false) {
            return new AccessTokenRefusal(AccessTokenRefusalReason::UNKNOWN, null, null);
        }
        $reason = match (true) {
            (bool)$row['grant_revoked'] => AccessTokenRefusalReason::GRANT_REVOKED,
            (bool)$row['token_revoked'] => AccessTokenRefusalReason::REVOKED,
            (bool)$row['expired'] => AccessTokenRefusalReason::EXPIRED,
            default => AccessTokenRefusalReason::OTHER_RESOURCE,
        };

        return new AccessTokenRefusal($reason, Rows::string($row, 'grant_id'), Rows::string($row, 'client_id'));
    }
}
