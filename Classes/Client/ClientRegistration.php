<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Client;

use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\DatabasePlatform;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Utility\Algorithms;

/**
 * Dynamic client registration (RFC 7591) for clients that bring no metadata
 * document. It registers public clients only; one that never got a grant is
 * removed by the garbage collection.
 */
#[Flow\Scope('singleton')]
class ClientRegistration
{
    private const int MAXIMUM_REDIRECT_URIS = 10;
    private const int MAXIMUM_NAME_LENGTH = 200;

    public function __construct(
        private readonly Connection $connection,
    ) {
    }

    /**
     * @param array<mixed> $metadata
     * @return array<string, mixed> the registration response
     * @throws InvalidClientMetadataException
     */
    public function register(array $metadata, string $registeredFrom): array
    {
        $redirectUris = $metadata['redirect_uris'] ?? null;
        if (!is_array($redirectUris) || $redirectUris === [] || !array_is_list($redirectUris) || count($redirectUris) > self::MAXIMUM_REDIRECT_URIS) {
            throw new InvalidClientMetadataException('invalid_redirect_uri', 'redirect_uris must list one to ten addresses', 1795083650);
        }
        $acceptedRedirectUris = [];
        foreach ($redirectUris as $redirectUri) {
            if (!is_string($redirectUri) || !RedirectUris::isAcceptable($redirectUri)) {
                throw new InvalidClientMetadataException('invalid_redirect_uri', 'A redirect URI must be https, or http to a loopback address, and at most 2048 bytes long', 1795083651);
            }
            $acceptedRedirectUris[] = $redirectUri;
        }
        if (($metadata['token_endpoint_auth_method'] ?? 'none') !== 'none') {
            throw new InvalidClientMetadataException('invalid_client_metadata', 'Only public clients are registered: token_endpoint_auth_method must be none', 1795083652);
        }
        if (!self::listsOnly($metadata['grant_types'] ?? [], ['authorization_code', 'refresh_token'])) {
            throw new InvalidClientMetadataException('invalid_client_metadata', 'Only authorization_code and refresh_token are granted', 1795083653);
        }
        if (!self::listsOnly($metadata['response_types'] ?? [], ['code'])) {
            throw new InvalidClientMetadataException('invalid_client_metadata', 'Only the response type code is supported', 1795083654);
        }
        $name = $metadata['client_name'] ?? null;
        $name = is_string($name) && trim($name) !== '' ? mb_substr(trim($name), 0, self::MAXIMUM_NAME_LENGTH) : RedirectUris::hostOf($acceptedRedirectUris[0]);

        $clientIdentifier = Algorithms::generateUUID();
        $issuedAt = time();
        [$createdAt, $issuedAtParameter] = match (DatabasePlatform::of($this->connection)) {
            DatabasePlatform::POSTGRESQL => ['to_timestamp(:issuedAt)', $issuedAt],
            DatabasePlatform::MYSQL => [':issuedAt', DatabasePlatform::MYSQL->timestamp(new DateTimeImmutable('@' . $issuedAt))],
        };
        $this->connection->executeStatement(
            "INSERT INTO flownative_oauth2_server_client (client_id, client_name, redirect_uris, origin, registered_from, created_at)
             VALUES (:clientId, :clientName, :redirectUris, 'registration', :registeredFrom, {$createdAt})",
            [
                'clientId' => $clientIdentifier,
                'clientName' => $name,
                'redirectUris' => json_encode($acceptedRedirectUris, JSON_THROW_ON_ERROR),
                'registeredFrom' => $registeredFrom,
                'issuedAt' => $issuedAtParameter,
            ]
        );

        return [
            'client_id' => $clientIdentifier,
            'client_id_issued_at' => $issuedAt,
            'client_name' => $name,
            'redirect_uris' => $acceptedRedirectUris,
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ];
    }

    /**
     * @param list<string> $allowed
     */
    private static function listsOnly(mixed $values, array $allowed): bool
    {
        if (!is_array($values)) {
            return false;
        }
        foreach ($values as $value) {
            if (!in_array($value, $allowed, true)) {
                return false;
            }
        }
        return true;
    }
}
