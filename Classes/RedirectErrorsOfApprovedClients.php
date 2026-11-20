<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use Doctrine\DBAL\Connection;
use Neos\Flow\Annotations as Flow;

/**
 * Sends errors back only to a client that a subject approved at this issuer
 * once, revoked grants included.
 */
#[Flow\Scope('singleton')]
final class RedirectErrorsOfApprovedClients implements ErrorRedirectPolicyInterface
{
    public function __construct(
        private readonly Connection $connection,
    ) {
    }

    public function mayRedirectErrors(Issuer $issuer, string $clientIdentifier): bool
    {
        return $this->connection->fetchOne(
            'SELECT 1 FROM flownative_oauth2_server_grant WHERE client_id = :clientId AND issuer = :issuer LIMIT 1',
            ['clientId' => $clientIdentifier, 'issuer' => $issuer->value]
        ) !== false;
    }
}
