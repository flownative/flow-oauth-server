<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Unit\Client;

use Closure;
use Flownative\OAuth2\Server\Client\ClientMetadataDocuments;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Yaml\Yaml;

class ClientMetadataDocumentsTest extends TestCase
{
    private const string CLIENT_ID = 'https://client.test/oauth/metadata.json';

    #[Test]
    public function aDocumentNamingItselfGivesTheClient(): void
    {
        $fetched = $this->documentsAnswering(['client_id' => self::CLIENT_ID, 'client_name' => 'Assistant', 'redirect_uris' => ['https://client.test/callback']], ['cache-control' => 'max-age=600'])->fetch(self::CLIENT_ID);

        self::assertNotNull($fetched);
        self::assertSame('Assistant', $fetched->client->name);
        self::assertSame(['https://client.test/callback'], $fetched->client->redirectUris);
        self::assertSame(600, $fetched->cacheLifetime);
    }

    #[Test]
    public function theCacheLifetimeIsCappedAtADay(): void
    {
        $fetched = $this->documentsAnswering(['client_id' => self::CLIENT_ID, 'redirect_uris' => ['https://client.test/callback']], ['cache-control' => 'max-age=9999999'])->fetch(self::CLIENT_ID);

        self::assertNotNull($fetched);
        self::assertSame(86400, $fetched->cacheLifetime);
        self::assertSame('client.test', $fetched->client->name, 'without a name the host stands in');
    }

    #[Test]
    public function aDocumentNamingAnotherClientIsRefused(): void
    {
        self::assertNull($this->documentsAnswering(['client_id' => 'https://other.test/metadata.json', 'redirect_uris' => ['https://client.test/callback']])->fetch(self::CLIENT_ID));
    }

    #[Test]
    public function aDocumentWithAnUnsafeRedirectIsRefused(): void
    {
        self::assertNull($this->documentsAnswering(['client_id' => self::CLIENT_ID, 'redirect_uris' => ['http://client.test/callback']])->fetch(self::CLIENT_ID));
    }

    #[Test]
    public function aLargeDocumentIsRefused(): void
    {
        $document = ['client_id' => self::CLIENT_ID, 'redirect_uris' => ['https://client.test/callback'], 'padding' => str_repeat('x', 6000)];

        self::assertNull($this->documentsAnswering($document)->fetch(self::CLIENT_ID));
    }

    #[Test]
    public function aHostGivenAsAnAddressIsNeverAsked(): void
    {
        $client = new MockHttpClient(new MockResponse('{}'));

        self::assertNull($this->documents($client)->fetch('https://93.184.215.14/metadata.json'));
        self::assertNull($this->documents($client)->fetch('https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]/metadata.json'));
        self::assertSame(0, $client->getRequestsCount());
    }

    #[Test]
    public function nameResolutionAndTheWholeFetchHaveOneTimeLimit(): void
    {
        $options = $this->optionsOfTheRequest();

        self::assertSame(5.0, $options['max_duration']);
        self::assertSame('*', $options['no_proxy']);
        self::assertSame(0, $options['max_redirects']);
        self::assertArrayNotHasKey('resolve', $options);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function deniedAddresses(): iterable
    {
        foreach ([
            '0.1.2.3', '10.0.0.5', '100.64.0.1', '100.127.255.254', '127.0.0.1', '169.254.169.254', '172.16.0.1', '172.31.255.255',
            '192.0.0.8', '192.0.2.1', '192.88.99.1', '192.168.1.1', '198.18.0.1', '198.19.255.254', '198.51.100.7', '203.0.113.9',
            '224.0.0.1', '240.0.0.1', '255.255.255.255', '::', '::1', '::127.0.0.1', '::ffff:10.0.0.1', '::ffff:127.0.0.1',
            '64:ff9b::a00:1', '64:ff9b:1::1', '100::1', '2001::1', '2001:db8::1', '2002:a00:1::1', 'fc00::1', 'fd12:3456::1',
            'fe80::1', 'fec0::1', 'ff02::1',
        ] as $address) {
            yield $address => [$address];
        }
        yield 'an address that is no IP' => ['client.test'];
        yield 'an empty address' => [''];
        yield 'an address with a port' => ['93.184.215.14:443'];
    }

    #[Test]
    #[DataProvider('deniedAddresses')]
    public function aConnectionToADeniedNetworkIsAbortedBeforeTheRequestIsSent(string $address): void
    {
        $beforeSending = $this->optionsOfTheRequest()['extra']['curl'][CURLOPT_PREREQFUNCTION];

        self::assertSame(CURL_PREREQFUNC_ABORT, $beforeSending(null, $address, '10.0.0.1', 443, 50000));
    }

    #[Test]
    #[DataProvider('deniedAddresses')]
    public function aDocumentFromADeniedNetworkIsRefused(string $address): void
    {
        $document = ['client_id' => self::CLIENT_ID, 'redirect_uris' => ['https://client.test/callback']];

        self::assertNull($this->documentsAnswering($document, [], $address)->fetch(self::CLIENT_ID));
    }

    #[Test]
    public function aPublicAddressIsAsked(): void
    {
        $beforeSending = $this->optionsOfTheRequest()['extra']['curl'][CURLOPT_PREREQFUNCTION];
        $document = ['client_id' => self::CLIENT_ID, 'redirect_uris' => ['https://client.test/callback']];
        foreach (['93.184.215.14', '100.128.0.1', '198.20.0.1', '2606:2800:21f:cb07:6820:80da:af6b:8b2c'] as $address) {
            self::assertSame(CURL_PREREQFUNC_OK, $beforeSending(null, $address, '10.0.0.1', 443, 50000), $address);
            self::assertNotNull($this->documentsAnswering($document, [], $address)->fetch(self::CLIENT_ID), $address);
        }
    }

    #[Test]
    public function aDocumentThatMayNotBeStoredIsKeptForTheMinimumLifetime(): void
    {
        $fetched = $this->documentsAnswering(['client_id' => self::CLIENT_ID, 'redirect_uris' => ['https://client.test/callback']], ['cache-control' => 'no-store'])->fetch(self::CLIENT_ID);

        self::assertNotNull($fetched);
        self::assertSame(60, $fetched->cacheLifetime, 'the request that fetched it must still find it');
    }

    #[Test]
    public function onlyAnHttpsAddressWithAPathAndNoQueryNamesADocument(): void
    {
        self::assertTrue(ClientMetadataDocuments::isDocumentAddress(self::CLIENT_ID));
        self::assertFalse(ClientMetadataDocuments::isDocumentAddress('http://client.test/metadata.json'));
        self::assertFalse(ClientMetadataDocuments::isDocumentAddress('https://client.test/'));
        self::assertFalse(ClientMetadataDocuments::isDocumentAddress('https://client.test/metadata.json?token=1'));
        self::assertFalse(ClientMetadataDocuments::isDocumentAddress('https://evil.test\\@client.test/metadata.json'));
        self::assertFalse(ClientMetadataDocuments::isDocumentAddress('3fa85f64-5717-4562-b3fc-2c963f66afa6'));
    }

    /**
     * @param array<string, mixed> $document
     * @param array<string, string> $headers
     */
    private function documentsAnswering(array $document, array $headers = [], string $primaryAddress = '93.184.215.14'): ClientMetadataDocuments
    {
        $client = new MockHttpClient(new MockResponse(json_encode($document, JSON_THROW_ON_ERROR), ['response_headers' => ['content-type' => 'application/json'] + $headers, 'primary_ip' => $primaryAddress]));
        return $this->documents($client);
    }

    /**
     * @return array{max_duration: float, no_proxy: string, max_redirects: int, extra: array{curl: array<int, Closure>}}
     */
    private function optionsOfTheRequest(): array
    {
        $options = [];
        $client = new MockHttpClient(static function (string $method, string $url, array $requestOptions) use (&$options): MockResponse {
            $options = $requestOptions;
            return new MockResponse('{}', ['http_code' => 404]);
        });
        $this->documents($client)->fetch(self::CLIENT_ID);
        /** @var array{max_duration: float, no_proxy: string, max_redirects: int, extra: array{curl: array<int, Closure>}} $options */
        return $options;
    }

    private function documents(MockHttpClient $client): ClientMetadataDocuments
    {
        $documents = new ClientMetadataDocuments($client);
        $settings = new ReflectionProperty($documents, 'settings');
        /** @var array{Flownative: array{OAuth2: array{Server: array{clientMetadataDocuments: array<string, mixed>}}}} $packageSettings */
        $packageSettings = Yaml::parseFile(__DIR__ . '/../../../Configuration/Settings.yaml');
        $settings->setValue($documents, $packageSettings['Flownative']['OAuth2']['Server']['clientMetadataDocuments']);
        return $documents;
    }
}
