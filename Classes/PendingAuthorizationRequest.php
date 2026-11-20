<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use DateTimeImmutable;
use DateTimeZone;
use Flownative\OAuth2\Server\Client\RedirectUris;
use Neos\Flow\Annotations as Flow;

/**
 * A validated authorization request waiting for the subject's answer on the
 * application's consent page.
 */
#[Flow\Proxy(false)]
final readonly class PendingAuthorizationRequest
{
    /**
     * @param list<string> $scopes
     */
    public function __construct(
        public string $identifier,
        public Issuer $issuer,
        public string $clientIdentifier,
        public string $clientName,
        public string $redirectUri,
        public ?string $state,
        public array $scopes,
        public string $codeChallenge,
        public string $resource,
        public DateTimeImmutable $expiresAt,
    ) {
    }

    /**
     * @param array<string, mixed> $row
     */
    public static function fromRow(array $row): self
    {
        return new self(
            Rows::string($row, 'request_id'),
            Issuer::fromString(Rows::string($row, 'issuer')),
            Rows::string($row, 'client_id'),
            Rows::string($row, 'client_name'),
            Rows::string($row, 'redirect_uri'),
            Rows::nullableString($row, 'state'),
            Rows::stringList($row, 'scopes'),
            Rows::string($row, 'code_challenge'),
            Rows::string($row, 'resource'),
            new DateTimeImmutable(Rows::string($row, 'expires_at'), new DateTimeZone('UTC')),
        );
    }

    /**
     * The host the code goes to, which the consent page shows prominently.
     */
    public function redirectHost(): string
    {
        return RedirectUris::hostOf($this->redirectUri);
    }

    public function redirectsToLoopback(): bool
    {
        return RedirectUris::isLoopback($this->redirectUri);
    }
}
