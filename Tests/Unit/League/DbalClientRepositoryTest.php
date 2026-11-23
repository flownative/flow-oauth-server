<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Unit\League;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\MySQLPlatform;
use Flownative\OAuth2\Server\Client\ClientMetadataDocuments;
use Flownative\OAuth2\Server\ClientMetadataFetchThrottleInterface;
use Flownative\OAuth2\Server\League\DbalClientRepository;
use Neos\Cache\Frontend\FrontendInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

class DbalClientRepositoryTest extends TestCase
{
    private const string DOCUMENT_ADDRESS = 'https://client.test/oauth/';

    #[Test]
    public function aMetadataDocumentAddressLongerThanTheTablesTakeIsUnknownWithoutAQuery(): void
    {
        $tooLong = self::documentAddressOfLength(769);
        self::assertTrue(ClientMetadataDocuments::isDocumentAddress($tooLong), 'only its length keeps the document from being fetched');
        $connection = $this->createMock(Connection::class);
        $connection->method('getDatabasePlatform')->willReturn(new MySQLPlatform());
        $connection->expects(self::never())->method('fetchAssociative');
        $connection->expects(self::never())->method('fetchOne');
        $connection->expects(self::never())->method('executeStatement');
        $metadataDocuments = $this->createMock(ClientMetadataDocuments::class);
        $metadataDocuments->expects(self::never())->method('fetch');
        $repository = $this->repository($connection, $metadataDocuments);

        $repository->learnFromMetadataDocument($tooLong, '192.0.2.1');

        self::assertNull($repository->getClientEntity($tooLong));
        self::assertFalse($repository->validateClient($tooLong, null, 'authorization_code'));
    }

    #[Test]
    public function theLimitCountsCharactersNotBytes(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('getDatabasePlatform')->willReturn(new MySQLPlatform());
        $connection->expects(self::never())->method('fetchAssociative');

        self::assertNull($this->repository($connection, $this->createStub(ClientMetadataDocuments::class))->getClientEntity(str_repeat('ä', 769)));
    }

    #[Test]
    public function aClientIdentifierOfTheLongestLengthIsLookedUp(): void
    {
        $longest = str_repeat('ä', 768);
        $connection = $this->createMock(Connection::class);
        $connection->method('getDatabasePlatform')->willReturn(new MySQLPlatform());
        $connection->expects(self::once())->method('fetchAssociative')->willReturn([
            'client_id' => $longest,
            'client_name' => 'Assistant',
            'redirect_uris' => '["https://client.test/callback"]',
        ]);

        $client = $this->repository($connection, $this->createStub(ClientMetadataDocuments::class))->getClientEntity($longest);

        self::assertNotNull($client);
        self::assertSame($longest, $client->getIdentifier());
    }

    private function repository(Connection $connection, ClientMetadataDocuments $metadataDocuments): DbalClientRepository
    {
        $throttle = $this->createStub(ClientMetadataFetchThrottleInterface::class);
        $throttle->method('allowsFetch')->willReturn(true);
        $repository = new DbalClientRepository($connection, $metadataDocuments, $throttle, $this->createStub(FrontendInterface::class));
        foreach (['metadataDocumentsEnabled' => true, 'refusalLifetime' => 600, 'staleIfErrorLifetime' => 86400] as $property => $value) {
            (new ReflectionProperty(DbalClientRepository::class, $property))->setValue($repository, $value);
        }
        return $repository;
    }

    private static function documentAddressOfLength(int $length): string
    {
        return self::DOCUMENT_ADDRESS . str_repeat('a', $length - strlen(self::DOCUMENT_ADDRESS));
    }
}
