<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use Doctrine\DBAL\Connection;
use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Utility\Algorithms;

/**
 * A grant is what a subject approved for one client; every code and token is
 * issued under one and dies with it. The subject is the application's to
 * name, the package never reads it. Revocations are announced by a signal.
 */
#[Flow\Scope('singleton')]
class Grants
{
    /**
     * The longest subject the tables take: MySQL indexes at most 768
     * characters. A longer one is refused on every database.
     */
    public const int MAXIMUM_SUBJECT_LENGTH = 768;

    public function __construct(
        private readonly Connection $connection,
    ) {
    }

    /**
     * @return non-empty-string the grant identifier
     */
    public function create(PendingAuthorizationRequest $request, string $subject): string
    {
        if (mb_strlen($subject) > self::MAXIMUM_SUBJECT_LENGTH) {
            throw new InvalidArgumentException(sprintf('A subject may be at most %d characters long', self::MAXIMUM_SUBJECT_LENGTH), 1795206411);
        }
        $grantIdentifier = Algorithms::generateUUID();
        assert($grantIdentifier !== '');
        $now = DatabasePlatform::of($this->connection)->now();
        $this->connection->executeStatement(
            "INSERT INTO flownative_oauth2_server_grant (grant_id, subject, client_id, client_name, redirect_uri, issuer, resource, scopes, created_at)
             VALUES (:grantId, :subject, :clientId, :clientName, :redirectUri, :issuer, :resource, :scopes, {$now})",
            [
                'grantId' => $grantIdentifier,
                'subject' => $subject,
                'clientId' => $request->clientIdentifier,
                'clientName' => $request->clientName,
                'redirectUri' => $request->redirectUri,
                'issuer' => $request->issuer->value,
                'resource' => $request->resource,
                'scopes' => json_encode($request->scopes, JSON_THROW_ON_ERROR),
            ]
        );
        return $grantIdentifier;
    }

    /**
     * Revokes the grant with all its codes and tokens; false if it was revoked already or never existed.
     */
    public function revoke(string $grantIdentifier): bool
    {
        if (!self::isGrantIdentifier($grantIdentifier)) {
            return false;
        }
        $subject = $this->connection->transactional(function (Connection $connection) use ($grantIdentifier): ?string {
            $subject = self::markRevoked($connection, $grantIdentifier);
            if ($subject === null) {
                return null;
            }
            $now = DatabasePlatform::of($connection)->now();
            $connection->executeStatement("UPDATE flownative_oauth2_server_access_token SET revoked_at = {$now} WHERE grant_id = :grantId AND revoked_at IS NULL", ['grantId' => $grantIdentifier]);
            $connection->executeStatement("UPDATE flownative_oauth2_server_refresh_token SET revoked_at = {$now} WHERE grant_id = :grantId AND revoked_at IS NULL", ['grantId' => $grantIdentifier]);
            $connection->executeStatement("UPDATE flownative_oauth2_server_authorization_code SET spent_at = {$now} WHERE grant_id = :grantId AND spent_at IS NULL", ['grantId' => $grantIdentifier]);
            $this->emitGrantRevoked($grantIdentifier, $subject);
            return $subject;
        });
        return $subject !== null;
    }

    /**
     * Revokes the grant behind an access or refresh token if the token was issued to the client (RFC 7009).
     */
    public function revokeByToken(string $token, string $clientIdentifier): bool
    {
        $grantIdentifier = $this->connection->fetchOne(
            'SELECT g.grant_id FROM flownative_oauth2_server_grant g
             WHERE g.client_id = :clientId AND g.grant_id IN (
                 SELECT grant_id FROM flownative_oauth2_server_access_token WHERE token_digest = :digest
                 UNION ALL
                 SELECT grant_id FROM flownative_oauth2_server_refresh_token WHERE token_digest = :digest
             )',
            ['digest' => TokenSecret::digest($token), 'clientId' => $clientIdentifier]
        );
        return is_string($grantIdentifier) && $this->revoke($grantIdentifier);
    }

    /**
     * @return int how many grants were revoked
     */
    public function revokeAllOf(string $subject): int
    {
        $grantIdentifiers = $this->connection->fetchFirstColumn(
            'SELECT grant_id FROM flownative_oauth2_server_grant WHERE subject = :subject AND revoked_at IS NULL',
            ['subject' => $subject]
        );
        $revoked = 0;
        foreach ($grantIdentifiers as $grantIdentifier) {
            if (is_string($grantIdentifier) && $this->revoke($grantIdentifier)) {
                $revoked++;
            }
        }
        return $revoked;
    }

    public function touch(string $grantIdentifier): void
    {
        $now = DatabasePlatform::of($this->connection)->now();
        $this->connection->executeStatement(
            "UPDATE flownative_oauth2_server_grant SET last_used_at = {$now} WHERE grant_id = :grantId",
            ['grantId' => $grantIdentifier]
        );
    }

    public static function isGrantIdentifier(string $value): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $value) === 1;
    }

    /**
     * Emitted inside the transaction that revokes, so that a slot can write in the same one.
     */
    #[Flow\Signal]
    protected function emitGrantRevoked(string $grantIdentifier, string $subject): void
    {
    }

    /**
     * Marks the grant revoked and returns its subject, or null if it was
     * revoked already or never existed. On MySQL the row lock decides: a
     * concurrent revocation waits for it and then finds the grant revoked.
     */
    private static function markRevoked(Connection $connection, string $grantIdentifier): ?string
    {
        if (DatabasePlatform::of($connection) === DatabasePlatform::POSTGRESQL) {
            $subject = $connection->fetchOne(
                'UPDATE flownative_oauth2_server_grant SET revoked_at = now() WHERE grant_id = :grantId AND revoked_at IS NULL RETURNING subject',
                ['grantId' => $grantIdentifier]
            );
            return is_string($subject) ? $subject : null;
        }
        $subject = $connection->fetchOne(
            'SELECT subject FROM flownative_oauth2_server_grant WHERE grant_id = :grantId AND revoked_at IS NULL FOR UPDATE',
            ['grantId' => $grantIdentifier]
        );
        if (!is_string($subject)) {
            return null;
        }
        $connection->executeStatement('UPDATE flownative_oauth2_server_grant SET revoked_at = UTC_TIMESTAMP(6) WHERE grant_id = :grantId', ['grantId' => $grantIdentifier]);
        return $subject;
    }
}
