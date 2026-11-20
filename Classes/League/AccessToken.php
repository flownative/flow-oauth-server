<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use Flownative\OAuth2\Server\TokenSecret;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use Neos\Flow\Annotations as Flow;

/**
 * An opaque access token instead of league's JWT. Its user identifier is the
 * grant it was issued under, and the secret handed out is the prefix followed
 * by the random identifier.
 */
#[Flow\Proxy(false)]
final class AccessToken implements AccessTokenEntityInterface
{
    use EntityTrait;
    use TokenEntityTrait;

    public function __construct(
        private readonly string $prefix,
    ) {
    }

    public function setPrivateKey(CryptKeyInterface $privateKey): void
    {
        // Nothing is signed: the token is a random secret.
    }

    public function toString(): string
    {
        return $this->prefix . $this->getIdentifier();
    }

    public function digest(): string
    {
        return TokenSecret::digest($this->toString());
    }
}
