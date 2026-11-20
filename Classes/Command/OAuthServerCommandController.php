<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Command;

use DateInterval;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\DatabasePlatform;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Cli\CommandController;

#[Flow\Scope('singleton')]
class OAuthServerCommandController extends CommandController
{
    #[Flow\InjectConfiguration(path: 'registration.unusedClientLifetime')]
    protected string $unusedClientLifetime;

    #[Flow\InjectConfiguration(path: 'clientMetadataDocuments.staleIfErrorLifetime')]
    protected int $staleIfErrorLifetime;

    public function __construct(
        private readonly Connection $connection,
    ) {
        parent::__construct();
    }

    /**
     * Remove what can no longer be used
     *
     * Removes expired authorization requests, codes and tokens, cached client
     * metadata documents that may no longer serve even while a fetch fails,
     * and registered clients that never got a grant. Grants stay, revoked
     * ones included.
     */
    public function collectGarbageCommand(): void
    {
        $platform = DatabasePlatform::of($this->connection);
        $now = $platform->now();
        $removed = [
            'authorization requests' => $this->connection->executeStatement("DELETE FROM flownative_oauth2_server_authorization_request WHERE expires_at < {$now}"),
            'authorization codes' => $this->connection->executeStatement("DELETE FROM flownative_oauth2_server_authorization_code WHERE expires_at < {$now}"),
            'access tokens' => $this->connection->executeStatement("DELETE FROM flownative_oauth2_server_access_token WHERE expires_at < {$now}"),
            'refresh tokens' => $this->connection->executeStatement("DELETE FROM flownative_oauth2_server_refresh_token WHERE expires_at < {$now} OR revoked_at IS NOT NULL"),
            'client metadata documents' => $this->removeStaleMetadataDocuments($platform),
            'unused clients' => $this->removeUnusedClients($platform),
        ];
        foreach ($removed as $what => $count) {
            $this->outputLine('%d %s removed', [$count, $what]);
        }
    }

    private function removeStaleMetadataDocuments(DatabasePlatform $platform): int|string
    {
        if ($platform === DatabasePlatform::MYSQL) {
            return $this->connection->executeStatement(
                "DELETE FROM flownative_oauth2_server_client WHERE origin = 'metadata_document' AND expires_at < :expiredBefore",
                ['expiredBefore' => $platform->timestamp(new DateTimeImmutable(sprintf('-%d seconds', $this->staleIfErrorLifetime)))]
            );
        }
        return $this->connection->executeStatement(
            "DELETE FROM flownative_oauth2_server_client WHERE origin = 'metadata_document' AND expires_at < now() - make_interval(secs => :staleIfErrorLifetime)",
            ['staleIfErrorLifetime' => $this->staleIfErrorLifetime]
        );
    }

    private function removeUnusedClients(DatabasePlatform $platform): int|string
    {
        if ($platform === DatabasePlatform::MYSQL) {
            // MariaDB takes no alias in a single-table DELETE.
            return $this->connection->executeStatement(
                "DELETE FROM flownative_oauth2_server_client WHERE origin = 'registration' AND created_at < :createdBefore
                 AND NOT EXISTS (SELECT 1 FROM flownative_oauth2_server_grant g WHERE g.client_id = flownative_oauth2_server_client.client_id)",
                ['createdBefore' => $platform->timestamp((new DateTimeImmutable())->sub(new DateInterval($this->unusedClientLifetime)))]
            );
        }
        return $this->connection->executeStatement(
            "DELETE FROM flownative_oauth2_server_client c WHERE c.origin = 'registration' AND c.created_at < now() - CAST(:lifetime AS interval)
                 AND NOT EXISTS (SELECT 1 FROM flownative_oauth2_server_grant g WHERE g.client_id = c.client_id)",
            ['lifetime' => $this->unusedClientLifetime]
        );
    }
}
