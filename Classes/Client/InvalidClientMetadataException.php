<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Client;

use Exception;

final class InvalidClientMetadataException extends Exception
{
    public function __construct(
        public readonly string $error,
        string $description,
        int $code,
    ) {
        parent::__construct($description, $code);
    }
}
