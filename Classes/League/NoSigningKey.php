<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use League\OAuth2\Server\CryptKeyInterface;
use Neos\Flow\Annotations as Flow;

/**
 * League's server takes a private key, but with opaque tokens and opaque
 * codes nothing is ever signed, so no key has to be kept and shared.
 */
#[Flow\Proxy(false)]
final class NoSigningKey implements CryptKeyInterface
{
    public function getKeyPath(): string
    {
        return '';
    }

    public function getPassPhrase(): ?string
    {
        return null;
    }

    public function getKeyContents(): string
    {
        return '';
    }
}
