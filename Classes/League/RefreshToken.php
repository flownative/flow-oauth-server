<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use Flownative\OAuth2\Server\TokenSecret;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use Neos\Flow\Annotations as Flow;

/**
 * An opaque refresh token instead of league's encrypted payload, so that a
 * refresh reads person, client and grant from the database alone.
 */
#[Flow\Proxy(false)]
final class RefreshToken implements RefreshTokenEntityInterface
{
    use EntityTrait;
    use RefreshTokenTrait;

    public function __construct(
        private readonly string $prefix,
    ) {
    }

    public function secret(): string
    {
        return $this->prefix . $this->getIdentifier();
    }

    public function digest(): string
    {
        return TokenSecret::digest($this->secret());
    }
}
