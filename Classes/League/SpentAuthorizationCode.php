<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use Flownative\OAuth2\Server\Rows;
use Neos\Flow\Annotations as Flow;
use RuntimeException;

#[Flow\Proxy(false)]
final readonly class SpentAuthorizationCode
{
    /**
     * @param non-empty-string $grantIdentifier
     * @param list<string> $scopes
     */
    public function __construct(
        public string $grantIdentifier,
        public string $redirectUri,
        public string $codeChallenge,
        public string $clientIdentifier,
        public string $resource,
        public array $scopes,
    ) {
    }

    /**
     * @param array<string, mixed> $row
     */
    public static function fromRow(array $row): self
    {
        $grantIdentifier = $row['grant_id'] ?? null;
        if (!is_string($grantIdentifier) || $grantIdentifier === '') {
            throw new RuntimeException('An authorization code row without a grant', 1795083655);
        }
        return new self(
            $grantIdentifier,
            Rows::string($row, 'redirect_uri'),
            Rows::string($row, 'code_challenge'),
            Rows::string($row, 'client_id'),
            Rows::string($row, 'resource'),
            Rows::stringList($row, 'scopes'),
        );
    }
}
