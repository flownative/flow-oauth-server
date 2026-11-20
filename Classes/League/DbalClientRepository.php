<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\Client\ClientMetadataDocuments;
use Flownative\OAuth2\Server\Client\FetchedClientMetadataDocument;
use Flownative\OAuth2\Server\ClientMetadataFetchThrottleInterface;
use Flownative\OAuth2\Server\DatabasePlatform;
use Flownative\OAuth2\Server\Rows;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Neos\Cache\Frontend\FrontendInterface;
use Neos\Flow\Annotations as Flow;

/**
 * Registered clients, and clients known by a metadata document at their
 * https client_id. League only reads the table; the middleware fetches a
 * document beforehand, outside any transaction. A refused document is not
 * asked again for a while, and an expired one keeps serving its client for
 * a bounded time while fetching it again fails.
 */
#[Flow\Scope('singleton')]
class DbalClientRepository implements ClientRepositoryInterface
{
    #[Flow\InjectConfiguration(path: 'clientMetadataDocuments.enabled')]
    protected bool $metadataDocumentsEnabled;

    #[Flow\InjectConfiguration(path: 'clientMetadataDocuments.refusalLifetime')]
    protected int $refusalLifetime; # seconds

    #[Flow\InjectConfiguration(path: 'clientMetadataDocuments.staleIfErrorLifetime')]
    protected int $staleIfErrorLifetime; # seconds

    public function __construct(
        private readonly Connection $connection,
        private readonly ClientMetadataDocuments $metadataDocuments,
        private readonly ClientMetadataFetchThrottleInterface $fetchThrottle,
        private readonly FrontendInterface $refusedDocuments,
    ) {
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        if ($clientIdentifier === '') {
            return null;
        }
        $row = $this->findServingClient($clientIdentifier);
        return $row === false ? null : new Client($clientIdentifier, Rows::string($row, 'client_name'), Rows::stringList($row, 'redirect_uris'));
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        return ($clientSecret === null || $clientSecret === '') && $this->getClientEntity($clientIdentifier) !== null;
    }

    /**
     * Fetches the metadata document of a client that is not known yet or whose
     * document expired, unless it was refused lately or the throttle holds the
     * source address back.
     */
    public function learnFromMetadataDocument(string $clientIdentifier, string $sourceAddress): void
    {
        if (!$this->metadataDocumentsEnabled || !ClientMetadataDocuments::isDocumentAddress($clientIdentifier)) {
            return;
        }
        $now = DatabasePlatform::of($this->connection)->now();
        $isKnown = $this->connection->fetchOne(
            "SELECT 1 FROM flownative_oauth2_server_client WHERE client_id = :clientId AND (origin = 'registration' OR expires_at > {$now})",
            ['clientId' => $clientIdentifier]
        ) !== false;
        if ($isKnown) {
            return;
        }
        $cacheEntryIdentifier = hash('sha256', $clientIdentifier);
        if ($this->refusedDocuments->has($cacheEntryIdentifier) || !$this->fetchThrottle->allowsFetch($sourceAddress)) {
            return;
        }
        $document = $this->metadataDocuments->fetch($clientIdentifier);
        if ($document === null) {
            $this->refusedDocuments->set($cacheEntryIdentifier, '1', [], $this->refusalLifetime);
            return;
        }
        $this->storeDocument($clientIdentifier, $document);
    }

    /**
     * A registered client, or one whose metadata document has not been
     * expired for longer than it may serve while fetching it again fails.
     *
     * @return array<string, mixed>|false
     */
    private function findServingClient(string $clientIdentifier): array|false
    {
        if (DatabasePlatform::of($this->connection) === DatabasePlatform::MYSQL) {
            return $this->connection->fetchAssociative(
                "SELECT client_id, client_name, redirect_uris FROM flownative_oauth2_server_client
                 WHERE client_id = :clientId AND (origin = 'registration' OR expires_at > :expiredAfter)",
                ['clientId' => $clientIdentifier, 'expiredAfter' => DatabasePlatform::MYSQL->timestamp(new DateTimeImmutable(sprintf('-%d seconds', $this->staleIfErrorLifetime)))]
            );
        }
        return $this->connection->fetchAssociative(
            "SELECT client_id, client_name, redirect_uris FROM flownative_oauth2_server_client
             WHERE client_id = :clientId AND (origin = 'registration' OR expires_at > now() - make_interval(secs => :staleIfErrorLifetime))",
            ['clientId' => $clientIdentifier, 'staleIfErrorLifetime' => $this->staleIfErrorLifetime]
        );
    }

    /**
     * Inserts the client of a document or updates it from a newer one; a
     * registered client of the same identifier stays as it is.
     */
    private function storeDocument(string $clientIdentifier, FetchedClientMetadataDocument $document): void
    {
        $redirectUris = json_encode($document->client->redirectUris, JSON_THROW_ON_ERROR);
        if (DatabasePlatform::of($this->connection) === DatabasePlatform::MYSQL) {
            // Each name appears once: a native prepared statement does not take a name twice.
            $expiresAt = DatabasePlatform::MYSQL->timestamp(new DateTimeImmutable(sprintf('+%d seconds', $document->cacheLifetime)));
            $this->connection->executeStatement(
                "INSERT INTO flownative_oauth2_server_client (client_id, client_name, redirect_uris, origin, created_at, expires_at)
                 VALUES (:clientId, :clientName, :redirectUris, 'metadata_document', UTC_TIMESTAMP(6), :expiresAt)
                 ON DUPLICATE KEY UPDATE
                    client_name = IF(origin = 'metadata_document', :updatedClientName, client_name),
                    redirect_uris = IF(origin = 'metadata_document', :updatedRedirectUris, redirect_uris),
                    expires_at = IF(origin = 'metadata_document', :updatedExpiresAt, expires_at)",
                [
                    'clientId' => $clientIdentifier,
                    'clientName' => $document->client->name,
                    'redirectUris' => $redirectUris,
                    'expiresAt' => $expiresAt,
                    'updatedClientName' => $document->client->name,
                    'updatedRedirectUris' => $redirectUris,
                    'updatedExpiresAt' => $expiresAt,
                ]
            );
            return;
        }
        $this->connection->executeStatement(
            "INSERT INTO flownative_oauth2_server_client (client_id, client_name, redirect_uris, origin, created_at, expires_at)
             VALUES (:clientId, :clientName, :redirectUris, 'metadata_document', now(), now() + make_interval(secs => :lifetime))
             ON CONFLICT (client_id) DO UPDATE SET client_name = EXCLUDED.client_name, redirect_uris = EXCLUDED.redirect_uris, expires_at = EXCLUDED.expires_at
             WHERE flownative_oauth2_server_client.origin = 'metadata_document'",
            [
                'clientId' => $clientIdentifier,
                'clientName' => $document->client->name,
                'redirectUris' => $redirectUris,
                'lifetime' => $document->cacheLifetime,
            ]
        );
    }
}
