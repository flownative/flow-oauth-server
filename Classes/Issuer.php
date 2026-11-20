<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use Stringable;

/**
 * The address the server answers under, scheme and host without a trailing
 * slash. Metadata, the iss parameter and the resource of every token derive
 * from it.
 */
#[Flow\Proxy(false)]
final readonly class Issuer implements Stringable
{
    private function __construct(
        public string $value,
    ) {
        $parts = parse_url($value);
        if (
            $parts === false
            || !in_array($parts['scheme'] ?? '', ['http', 'https'], true)
            || ($parts['host'] ?? '') === ''
            || isset($parts['path'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || isset($parts['user'])
        ) {
            throw new InvalidArgumentException(sprintf('"%s" is no issuer: it takes a scheme and a host, nothing else', $value), 1795083639);
        }
    }

    public static function fromString(string $value): self
    {
        return new self($value);
    }

    public function uriOf(string $path): string
    {
        return $this->value . '/' . ltrim($path, '/');
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
