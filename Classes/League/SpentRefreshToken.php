<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use Flownative\OAuth2\Server\Rows;
use Neos\Flow\Annotations as Flow;
use RuntimeException;

#[Flow\Proxy(false)]
final readonly class SpentRefreshToken
{
    /**
     * @param non-empty-string $grantIdentifier
     * @param list<string> $scopes
     */
    public function __construct(
        public string $grantIdentifier,
        public string $accessTokenDigest,
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
            throw new RuntimeException('A refresh token row without a grant', 1795083646);
        }
        return new self(
            $grantIdentifier,
            Rows::string($row, 'access_token_digest'),
            Rows::string($row, 'client_id'),
            Rows::string($row, 'resource'),
            Rows::stringList($row, 'scopes'),
        );
    }
}
