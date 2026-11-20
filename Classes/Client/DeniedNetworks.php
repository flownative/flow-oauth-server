<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Client;

use InvalidArgumentException;

/**
 * The networks a client metadata document is never fetched from, as CIDR
 * ranges. Whatever is no valid IP address counts as denied.
 */
final readonly class DeniedNetworks
{
    /**
     * @param list<array{string, int}> $networks packed network address and prefix length
     */
    private function __construct(
        private array $networks,
    ) {
    }

    /**
     * @param list<string> $cidrRanges
     */
    public static function fromCidrRanges(array $cidrRanges): self
    {
        $networks = [];
        foreach ($cidrRanges as $cidrRange) {
            [$address, $prefixLength] = array_pad(explode('/', $cidrRange, 2), 2, '');
            $packedAddress = filter_var($address, FILTER_VALIDATE_IP) === false ? false : inet_pton($address);
            if (!is_string($packedAddress) || preg_match('/^\d{1,3}$/', $prefixLength) !== 1 || (int)$prefixLength > strlen($packedAddress) * 8) {
                throw new InvalidArgumentException(sprintf('"%s" is no CIDR range', $cidrRange), 1795120001);
            }
            $networks[] = [$packedAddress, (int)$prefixLength];
        }
        return new self($networks);
    }

    public function contains(string $address): bool
    {
        $packedAddress = filter_var($address, FILTER_VALIDATE_IP) === false ? false : inet_pton($address);
        if (!is_string($packedAddress)) {
            return true;
        }
        foreach ($this->networks as [$packedNetwork, $prefixLength]) {
            if (strlen($packedNetwork) === strlen($packedAddress) && self::prefixOf($packedAddress, $prefixLength) === self::prefixOf($packedNetwork, $prefixLength)) {
                return true;
            }
        }
        return false;
    }

    private static function prefixOf(string $packedAddress, int $prefixLength): string
    {
        $wholeBytes = intdiv($prefixLength, 8);
        $remainingBits = $prefixLength % 8;
        $prefix = substr($packedAddress, 0, $wholeBytes);
        if ($remainingBits > 0) {
            $prefix .= chr(ord($packedAddress[$wholeBytes]) & (0xFF << (8 - $remainingBits)) & 0xFF);
        }
        return $prefix;
    }
}
