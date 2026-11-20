<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Functional;

use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\Client\ClientMetadataDocuments;
use Flownative\OAuth2\Server\ClientMetadataFetchThrottleInterface;
use Flownative\OAuth2\Server\Endpoints;
use Flownative\OAuth2\Server\Grants;
use Flownative\OAuth2\Server\League\AuthorizationCodes;
use Flownative\OAuth2\Server\League\AuthorizationServerFactory;
use Flownative\OAuth2\Server\League\ConfiguredScopeRepository;
use Flownative\OAuth2\Server\League\DbalAccessTokenRepository;
use Flownative\OAuth2\Server\League\DbalClientRepository;
use Flownative\OAuth2\Server\League\DbalRefreshTokenRepository;
use Neos\Flow\Cache\CacheManager;
use Neos\Flow\Configuration\ConfigurationManager;
use PHPUnit\Framework\Attributes\Test;
use ReflectionProperty;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Runs the middleware with a client repository whose fetcher answers from
 * memory, and counts what it is asked.
 */
class ClientMetadataDocumentTest extends AuthorizationServerTestCase
{
    private const string GOOD_CLIENT_ID = 'https://good.client.test/metadata.json';
    private const string BAD_CLIENT_ID = 'https://bad.client.test/metadata.json';

    /**
     * @var list<bool> whether a transaction was open, per fetch
     */
    private array $fetches = [];

    /**
     * @var list<string>
     */
    private array $throttledAddresses = [];

    private bool $throttleAllows = true;

    private bool $documentAnswers = true;

    private ClientMetadataDocuments $originalDocuments;

    private DbalClientRepository $originalClients;

    private AuthorizationServerFactory $originalFactory;

    protected function setUp(): void
    {
        parent::setUp();
        $connection = $this->objectManager->get(Connection::class);
        $refusedDocuments = $this->objectManager->get(CacheManager::class)->getCache('Flownative_OAuth2_Server_RefusedClientMetadataDocuments');
        $refusedDocuments->flush();
        $httpClient = new MockHttpClient(function (string $method, string $url) use ($connection): MockResponse {
            $this->fetches[] = $connection->isTransactionActive();
            if ($url !== self::GOOD_CLIENT_ID || !$this->documentAnswers) {
                return new MockResponse('', ['http_code' => 404, 'primary_ip' => '93.184.215.14']);
            }
            $document = ['client_id' => $url, 'client_name' => 'Document client', 'redirect_uris' => [self::REDIRECT_URI]];
            return new MockResponse(json_encode($document, JSON_THROW_ON_ERROR), ['primary_ip' => '93.184.215.14', 'response_headers' => ['content-type' => 'application/json', 'cache-control' => 'no-store']]);
        });
        $throttle = new class ($this) implements ClientMetadataFetchThrottleInterface {
            public function __construct(private readonly ClientMetadataDocumentTest $test)
            {
            }

            public function allowsFetch(string $sourceAddress): bool
            {
                return $this->test->throttle($sourceAddress);
            }
        };
        // A singleton made with new registers itself, so the originals are taken before.
        $this->originalDocuments = $this->objectManager->get(ClientMetadataDocuments::class);
        $this->originalClients = $this->objectManager->get(DbalClientRepository::class);
        $this->originalFactory = $this->objectManager->get(AuthorizationServerFactory::class);
        $documents = new ClientMetadataDocuments($httpClient);
        $settings = $this->objectManager->get(ConfigurationManager::class)->getConfiguration(ConfigurationManager::CONFIGURATION_TYPE_SETTINGS, 'Flownative.OAuth2.Server.clientMetadataDocuments');
        (new ReflectionProperty($documents, 'settings'))->setValue($documents, $settings);
        $clients = new DbalClientRepository($connection, $documents, $throttle, $refusedDocuments);
        $this->objectManager->setInstance(DbalClientRepository::class, $clients);
        $this->objectManager->setInstance(AuthorizationServerFactory::class, new AuthorizationServerFactory(
            $clients,
            $this->objectManager->get(DbalAccessTokenRepository::class),
            $this->objectManager->get(DbalRefreshTokenRepository::class),
            $this->objectManager->get(ConfiguredScopeRepository::class),
            $this->objectManager->get(AuthorizationCodes::class),
            $this->objectManager->get(Grants::class),
            $this->objectManager->get(Endpoints::class),
        ));
    }

    protected function tearDown(): void
    {
        $this->objectManager->setInstance(ClientMetadataDocuments::class, $this->originalDocuments);
        $this->objectManager->setInstance(DbalClientRepository::class, $this->originalClients);
        $this->objectManager->setInstance(AuthorizationServerFactory::class, $this->originalFactory);
        parent::tearDown();
    }

    public function throttle(string $sourceAddress): bool
    {
        $this->throttledAddresses[] = $sourceAddress;
        return $this->throttleAllows;
    }

    #[Test]
    public function aDocumentIsFetchedOnceOutsideTheTokenTransaction(): void
    {
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $response = $this->post('/oauth/token', ['grant_type' => 'authorization_code', 'client_id' => self::GOOD_CLIENT_ID, 'code' => 'unknown', 'code_verifier' => self::CODE_VERIFIER]);
            self::assertSame('invalid_grant', self::json($response)['error'], 'the client is known, only the code is not');
        }

        self::assertSame([false], $this->fetches, 'the rolled back exchanges keep the client, even of a document that may not be stored');
        self::assertSame([self::CLIENT_IP_ADDRESS], $this->throttledAddresses);
    }

    #[Test]
    public function aClientOfADocumentGetsThroughToTheConsentPage(): void
    {
        $response = $this->authorize(self::GOOD_CLIENT_ID);

        self::assertSame(302, $response->getStatusCode(), (string)$response->getBody());
        self::assertStringStartsWith(self::ISSUER . '/oauth/consent?request=', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function aRefusedDocumentIsNotFetchedAgainForAWhile(): void
    {
        for ($attempt = 0; $attempt < 3; $attempt++) {
            self::assertSame(400, $this->authorize(self::BAD_CLIENT_ID)->getStatusCode());
        }

        self::assertCount(1, $this->fetches);
    }

    #[Test]
    public function theThrottleCanHoldAFetchBack(): void
    {
        $this->throttleAllows = false;

        self::assertSame(400, $this->authorize(self::GOOD_CLIENT_ID)->getStatusCode());

        self::assertSame([], $this->fetches);
        self::assertSame([self::CLIENT_IP_ADDRESS], $this->throttledAddresses);
    }

    #[Test]
    public function anExpiredDocumentKeepsItsClientForADayWhileFetchingItAgainFails(): void
    {
        self::assertSame(302, $this->authorize(self::GOOD_CLIENT_ID)->getStatusCode());
        $this->documentAnswers = false;
        $connection = $this->objectManager->get(Connection::class);
        $connection->executeStatement("UPDATE flownative_oauth2_server_client SET expires_at = now() - interval '1 hour' WHERE client_id = :clientId", ['clientId' => self::GOOD_CLIENT_ID]);

        self::assertSame(302, $this->authorize(self::GOOD_CLIENT_ID)->getStatusCode(), 'a failing fetch keeps the client it served');
        self::assertCount(2, $this->fetches, 'the expired document is asked again');

        $connection->executeStatement("UPDATE flownative_oauth2_server_client SET expires_at = now() - interval '25 hours' WHERE client_id = :clientId", ['clientId' => self::GOOD_CLIENT_ID]);
        self::assertSame(400, $this->authorize(self::GOOD_CLIENT_ID)->getStatusCode());
    }
}
