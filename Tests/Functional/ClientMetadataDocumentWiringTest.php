<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Functional;

use Flownative\OAuth2\Server\Client\ClientMetadataDocuments;
use Neos\Flow\Cache\CacheManager;
use Neos\Utility\ObjectAccess;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\LoggerInterface;

/**
 * Runs the authorization request against the fetcher as the object manager
 * builds it, with nothing replaced.
 */
class ClientMetadataDocumentWiringTest extends AuthorizationServerTestCase
{
    #[Test]
    public function theFetcherOfTheObjectManagerHasItsSettingsAndLogger(): void
    {
        $documents = $this->objectManager->get(ClientMetadataDocuments::class);

        self::assertIsArray(ObjectAccess::getProperty($documents, 'settings', true));
        self::assertInstanceOf(LoggerInterface::class, ObjectAccess::getProperty($documents, 'logger', true));
    }

    #[Test]
    public function aDocumentOnADeniedHostIsRefusedWithoutAnError(): void
    {
        $this->objectManager->get(CacheManager::class)->getCache('Flownative_OAuth2_Server_RefusedClientMetadataDocuments')->flush();

        $response = $this->authorize('https://localhost/metadata.json');

        self::assertSame(400, $response->getStatusCode(), (string)$response->getBody());
    }
}
