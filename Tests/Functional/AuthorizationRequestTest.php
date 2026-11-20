<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Functional;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception as DbalException;
use Flownative\OAuth2\Server\AuthorizationRequests;
use Flownative\OAuth2\Server\DatabasePlatform;
use Flownative\OAuth2\Server\Issuer;
use Flownative\OAuth2\Server\League\AuthorizationCodes;
use Flownative\OAuth2\Server\League\DbalClientRepository;
use Flownative\OAuth2\Server\League\DbalRefreshTokenRepository;
use Flownative\OAuth2\Server\Tests\Functional\Fixtures\SpendingProcess;
use Flownative\OAuth2\Server\UnknownAuthorizationRequestException;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class AuthorizationRequestTest extends AuthorizationServerTestCase
{
    #[Test]
    public function theMetadataNamesTheEndpointsAndS256Only(): void
    {
        $metadata = self::json($this->send('GET', '/.well-known/oauth-authorization-server'));

        self::assertSame(self::ISSUER, $metadata['issuer']);
        self::assertSame(self::ISSUER . '/oauth/token', $metadata['token_endpoint']);
        self::assertSame(self::ISSUER . '/oauth/register', $metadata['registration_endpoint']);
        self::assertSame(['S256'], $metadata['code_challenge_methods_supported']);
        self::assertSame(['none'], $metadata['token_endpoint_auth_methods_supported']);
        self::assertTrue($metadata['client_id_metadata_document_supported']);
        self::assertTrue($metadata['authorization_response_iss_parameter_supported']);
        self::assertStringStartsWith('private', $this->send('GET', '/.well-known/oauth-authorization-server')->getHeaderLine('Cache-Control'), 'a shared cache must not answer another host with it');

        $resource = self::json($this->send('GET', '/.well-known/oauth-protected-resource/mcp'));
        self::assertSame(self::ISSUER . '/mcp', $resource['resource']);
        self::assertSame([self::ISSUER], $resource['authorization_servers']);
        self::assertSame(['mcp'], $resource['scopes_supported']);
    }

    #[Test]
    public function aValidRequestWaitsForTheConsentPage(): void
    {
        $response = $this->authorize($this->registerClient());

        self::assertSame(302, $response->getStatusCode(), (string)$response->getBody());
        self::assertStringStartsWith(self::ISSUER . '/oauth/consent?request=', $response->getHeaderLine('Location'));
        $requestIdentifier = self::queryOf($response->getHeaderLine('Location'))['request'] ?? null;
        self::assertIsString($requestIdentifier);
        $pending = $this->objectManager->get(AuthorizationRequests::class)->find($requestIdentifier, $this->issuer());
        self::assertNotNull($pending);
        self::assertSame('Test client', $pending->clientName);
        self::assertSame('client.test', $pending->redirectHost());
        self::assertSame(self::ISSUER . '/mcp', $pending->resource, 'a missing resource is taken as the canonical one');
        self::assertNull($this->objectManager->get(AuthorizationRequests::class)->find($requestIdentifier, Issuer::fromString('https://other.test')));
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function refusedAfterTheRedirectIsProved(): iterable
    {
        yield 'plain PKCE' => [['code_challenge_method' => 'plain'], 'invalid_request'];
        yield 'no PKCE method' => [['code_challenge_method' => ''], 'invalid_request'];
        yield 'no PKCE' => [['code_challenge' => '', 'code_challenge_method' => ''], 'invalid_request'];
        yield 'another response type' => [['response_type' => 'token'], 'unsupported_response_type'];
        yield 'another resource' => [['resource' => 'https://other.test/mcp'], 'invalid_target'];
        yield 'an unknown scope' => [['scope' => 'admin'], 'invalid_scope'];
    }

    /**
     * @param array<string, string> $overrides
     */
    #[Test]
    #[DataProvider('refusedAfterTheRedirectIsProved')]
    public function aRefusalGoesBackToAnApprovedClientWithStateAndIssuer(array $overrides, string $error): void
    {
        $clientIdentifier = $this->registerClient();
        $this->codeFor($clientIdentifier);

        $response = $this->authorize($clientIdentifier, $overrides);

        self::assertSame(302, $response->getStatusCode(), (string)$response->getBody());
        self::assertStringStartsWith(self::REDIRECT_URI . '?', $response->getHeaderLine('Location'));
        $parameters = self::queryOf($response->getHeaderLine('Location'));
        self::assertSame($error, $parameters['error']);
        self::assertSame('state-of-the-client', $parameters['state']);
        self::assertSame(self::ISSUER, $parameters['iss']);
    }

    #[Test]
    public function aRefusalForAClientNobodyApprovedStaysWithTheServer(): void
    {
        $clientIdentifier = $this->registerClient(['https://attacker.test/landing']);

        $response = $this->authorize($clientIdentifier, ['response_type' => 'x', 'redirect_uri' => 'https://attacker.test/landing']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('', $response->getHeaderLine('Location'), 'a self-registered client must not turn the server into an open redirect');
        self::assertStringStartsWith('unsupported_response_type', (string)$response->getBody());
    }

    #[Test]
    public function anUnprovedRedirectIsNeverFollowed(): void
    {
        $clientIdentifier = $this->registerClient();

        $foreignRedirect = $this->authorize($clientIdentifier, ['redirect_uri' => 'https://attacker.test/callback']);
        $unknownClient = $this->authorize('unknown-client');

        self::assertSame(400, $foreignRedirect->getStatusCode());
        self::assertSame('', $foreignRedirect->getHeaderLine('Location'));
        self::assertSame(400, $unknownClient->getStatusCode());
        self::assertSame('', $unknownClient->getHeaderLine('Location'));
    }

    #[Test]
    public function aLoopbackRedirectMatchesOnAnyPort(): void
    {
        $clientIdentifier = $this->registerClient(['http://localhost/callback', 'http://127.0.0.1/callback']);

        $response = $this->authorize($clientIdentifier, ['redirect_uri' => 'http://127.0.0.1:53682/callback']);
        $otherPath = $this->authorize($clientIdentifier, ['redirect_uri' => 'http://127.0.0.1:53682/other']);

        self::assertSame(302, $response->getStatusCode(), (string)$response->getBody());
        self::assertStringStartsWith(self::ISSUER . '/oauth/consent', $response->getHeaderLine('Location'));
        self::assertSame(400, $otherPath->getStatusCode());
    }

    #[Test]
    public function aLoopbackRedirectThatABrowserReadsAsAnotherHostIsRefused(): void
    {
        $clientIdentifier = $this->registerClient(['http://localhost/callback']);

        foreach (['http://attacker.test\\@localhost/callback', 'http://attacker.test@localhost:1234/callback', 'http://attacker.test%5C@localhost/callback'] as $redirectUri) {
            $response = $this->authorize($clientIdentifier, ['redirect_uri' => $redirectUri]);
            self::assertSame(400, $response->getStatusCode(), $redirectUri);
            self::assertSame('', $response->getHeaderLine('Location'), $redirectUri);
        }
    }

    #[Test]
    public function aDenialRedirectsWithAccessDeniedAndSpendsTheRequest(): void
    {
        $response = $this->authorize($this->registerClient());
        $requestIdentifier = self::queryOf($response->getHeaderLine('Location'))['request'] ?? null;
        self::assertIsString($requestIdentifier);
        $requests = $this->objectManager->get(AuthorizationRequests::class);

        $parameters = self::queryOf($requests->deny($requestIdentifier, $this->issuer()));

        self::assertSame('access_denied', $parameters['error']);
        self::assertSame(self::ISSUER, $parameters['iss']);
        $this->expectException(UnknownAuthorizationRequestException::class);
        $requests->approve($requestIdentifier, $this->issuer(), 'subject-1');
    }

    #[Test]
    public function registrationRefusesWhatIsNoPublicClientWithSafeRedirects(): void
    {
        $insecure = $this->send('POST', '/oauth/register', json_encode(['redirect_uris' => ['http://client.test/callback']], JSON_THROW_ON_ERROR));
        $confidential = $this->send('POST', '/oauth/register', json_encode(['redirect_uris' => [self::REDIRECT_URI], 'token_endpoint_auth_method' => 'client_secret_basic'], JSON_THROW_ON_ERROR));

        self::assertSame('invalid_redirect_uri', self::json($insecure)['error']);
        self::assertSame('invalid_client_metadata', self::json($confidential)['error']);
        $backslash = $this->send('POST', '/oauth/register', json_encode(['redirect_uris' => ['http://attacker.test\\@localhost/callback']], JSON_THROW_ON_ERROR));
        self::assertSame('invalid_redirect_uri', self::json($backslash)['error']);
        $manyVariables = $this->send('POST', '/oauth/register', json_encode(['redirect_uris' => ['https://attacker.test/landing?' . http_build_query(array_fill_keys(array_map(static fn (int $number): string => 'v' . $number, range(1, 1000)), ''))]], JSON_THROW_ON_ERROR));
        self::assertSame('invalid_redirect_uri', self::json($manyVariables)['error'], 'an address longer than 2 kB');
        $tooMany = $this->send('POST', '/oauth/register', json_encode(['redirect_uris' => array_map(static fn (int $number): string => 'https://client.test/callback' . $number, range(1, 11))], JSON_THROW_ON_ERROR));
        self::assertSame('invalid_redirect_uri', self::json($tooMany)['error'], 'more than ten addresses');
    }

    #[Test]
    public function registrationKeepsTheAddressOfTheClientBehindTheProxy(): void
    {
        $clientIdentifier = $this->registerClient();

        $registeredFrom = $this->objectManager->get(Connection::class)->fetchOne('SELECT registered_from FROM flownative_oauth2_server_client WHERE client_id = ?', [$clientIdentifier]);
        self::assertSame(self::CLIENT_IP_ADDRESS, $registeredFrom);
    }

    #[Test]
    public function aBodyArrivingInPiecesIsReadWholeUpToItsLimit(): void
    {
        $metadata = json_encode(['client_name' => str_repeat('n', 150), 'redirect_uris' => [self::REDIRECT_URI]], JSON_THROW_ON_ERROR);
        $whole = $this->send('POST', '/oauth/register', self::inPieces($metadata), ['Content-Type' => 'application/json']);
        $tooLarge = $this->send('POST', '/oauth/register', self::inPieces(str_repeat(' ', 16384) . $metadata), ['Content-Type' => 'application/json']);
        $tooLargeForm = $this->send('POST', '/oauth/token', self::inPieces('grant_type=authorization_code&padding=' . str_repeat('x', 16384)), ['Content-Type' => 'application/x-www-form-urlencoded']);

        self::assertSame(201, $whole->getStatusCode(), (string)$whole->getBody());
        self::assertSame(str_repeat('n', 150), self::json($whole)['client_name']);
        self::assertSame(413, $tooLarge->getStatusCode());
        self::assertSame(413, $tooLargeForm->getStatusCode());
    }

    #[Test]
    public function anIdentifierOnlyMatchesItself(): void
    {
        $clientIdentifier = $this->registerClient();
        $clients = $this->objectManager->get(DbalClientRepository::class);

        self::assertNotNull($clients->getClientEntity($clientIdentifier));
        self::assertNull($clients->getClientEntity($clientIdentifier . ' '), 'trailing spaces count');
    }

    #[Test]
    #[DataProvider('spendings')]
    public function aCredentialIsSpentOnceEvenWhenTwoExchangesRace(string $credential): void
    {
        $clientIdentifier = $this->registerClient();
        $code = $this->codeFor($clientIdentifier);
        $refreshToken = null;
        if ($credential === 'refresh token') {
            $refreshToken = self::json($this->exchange($clientIdentifier, $code))['refresh_token'] ?? null;
            self::assertIsString($refreshToken);
        }
        $connection = $this->objectManager->get(Connection::class);
        $codes = $this->objectManager->get(AuthorizationCodes::class);
        $refreshTokens = $this->objectManager->get(DbalRefreshTokenRepository::class);
        $secondConnection = DriverManager::getConnection($connection->getParams());
        $secondConnection->executeStatement(match ($this->databasePlatform()) {
            DatabasePlatform::POSTGRESQL => "SET lock_timeout = '200ms'",
            DatabasePlatform::MYSQL => 'SET SESSION innodb_lock_wait_timeout = 1',
        });
        $spend = static fn (Connection $connection): ?object => $refreshToken === null
            ? (new AuthorizationCodes($connection))->spend($code)
            : (new DbalRefreshTokenRepository($connection))->spend($refreshToken);

        $connection->beginTransaction();
        try {
            self::assertNotNull($spend($connection));
            try {
                $spend($secondConnection);
                self::fail('A second exchange spent the credential while the first one held it');
            } catch (DbalException) {
                // The second exchange waits for the first one's row.
            }
            $connection->commit();
        } finally {
            if ($connection->isTransactionActive()) {
                $connection->rollBack();
            }
        }

        self::assertNull($spend($secondConnection), 'after the first one committed, the credential is spent');
        $secondConnection->close();
        // A singleton made with new registers itself in its place.
        $this->objectManager->setInstance(AuthorizationCodes::class, $codes);
        $this->objectManager->setInstance(DbalRefreshTokenRepository::class, $refreshTokens);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function spendings(): iterable
    {
        yield 'a code' => ['code'];
        yield 'a refresh token' => ['refresh token'];
    }

    #[Test]
    #[DataProvider('spendings')]
    public function spendingLocksTheGrantFirstAsRevokingDoes(string $credential): void
    {
        $clientIdentifier = $this->registerClient();
        $code = $this->codeFor($clientIdentifier);
        $refreshToken = null;
        if ($credential === 'refresh token') {
            $refreshToken = self::json($this->exchange($clientIdentifier, $code))['refresh_token'] ?? null;
            self::assertIsString($refreshToken);
        }
        $connection = $this->objectManager->get(Connection::class);
        $secondConnection = DriverManager::getConnection($connection->getParams());

        $connection->beginTransaction();
        try {
            $spent = $refreshToken === null
                ? (new AuthorizationCodes($connection))->spend($code)
                : (new DbalRefreshTokenRepository($connection))->spend($refreshToken);
            self::assertNotNull($spent);
            try {
                $secondConnection->fetchOne('SELECT grant_id FROM flownative_oauth2_server_grant WHERE grant_id = :grantId FOR UPDATE NOWAIT', ['grantId' => $spent->grantIdentifier]);
                self::fail('Spending left the grant row free, so a revocation could lock it and wait for the token row');
            } catch (DbalException) {
                // The grant row is held, as a revocation takes it first.
            }
        } finally {
            $connection->rollBack();
            $secondConnection->close();
        }
    }

    #[Test]
    #[DataProvider('spendings')]
    public function aCredentialPresentedAgainInARaceRevokesTheGrant(string $credential): void
    {
        $clientIdentifier = $this->registerClient();
        $secret = $this->codeFor($clientIdentifier);
        if ($credential === 'refresh token') {
            $secret = self::json($this->exchange($clientIdentifier, $secret))['refresh_token'] ?? null;
            self::assertIsString($secret);
        }

        // Spent outside the retry grace period, so that a refresh token presented again is a reuse.
        $response = $this->presentWhileAnotherExchangeHoldsIt($credential, $secret, $clientIdentifier, 60);

        self::assertSame('invalid_grant', self::json($response)['error']);
        self::assertTrue($this->grantOfClientIsRevoked($clientIdentifier), 'the exchange which waited for the first one sees the credential spent before');
    }

    #[Test]
    public function aRefreshTokenPresentedAgainInARaceWithinTheGracePeriodLeavesTheGrant(): void
    {
        $clientIdentifier = $this->registerClient();
        $refreshToken = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)))['refresh_token'] ?? null;
        self::assertIsString($refreshToken);

        $response = $this->presentWhileAnotherExchangeHoldsIt('refresh token', $refreshToken, $clientIdentifier);

        self::assertSame('invalid_grant', self::json($response)['error']);
        self::assertFalse($this->grantOfClientIsRevoked($clientIdentifier), 'the exchange which waited for the first one sees when the token was spent');
    }

    /**
     * Another process spends the credential and holds its transaction open,
     * while this one presents the credential through the token endpoint and
     * waits for the locks.
     */
    private function presentWhileAnotherExchangeHoldsIt(string $credential, string $secret, string $clientIdentifier, int $spentSecondsAgo = 0): ResponseInterface
    {
        $process = proc_open(SpendingProcess::command(), [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($process);
        fwrite($pipes[0], json_encode([
            'connection' => self::plainConnectionParameters($this->objectManager->get(Connection::class)->getParams()),
            'credential' => $credential,
            'secret' => $secret,
            'holdSeconds' => 1,
            'spentSecondsAgo' => $spentSecondsAgo,
        ], JSON_THROW_ON_ERROR));
        fclose($pipes[0]);
        $said = fgets($pipes[1]);
        if ($said !== "held\n") {
            self::fail('The first exchange did not spend the credential: ' . $said . stream_get_contents($pipes[2]));
        }

        $startedAt = microtime(true);
        $response = $credential === 'code' ? $this->exchange($clientIdentifier, $secret) : $this->refresh($clientIdentifier, $secret);
        $waited = microtime(true) - $startedAt;

        stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);
        self::assertSame(0, proc_close($process), 'the first exchange committed: ' . $errors);
        self::assertGreaterThan(0.5, $waited, 'the second exchange waited for the first one');
        return $response;
    }

    private function grantOfClientIsRevoked(string $clientIdentifier): bool
    {
        $revokedAt = $this->objectManager->get(Connection::class)->fetchOne('SELECT revoked_at FROM flownative_oauth2_server_grant WHERE client_id = :clientId', ['clientId' => $clientIdentifier]);
        self::assertNotFalse($revokedAt, 'the client has a grant');
        return $revokedAt !== null;
    }

    /**
     * Only what reaches the database: an application's own driver, wrapper or
     * middlewares may need constructor arguments the spending process cannot give.
     *
     * @param array<string, mixed> $parameters
     * @return array<string, mixed>
     */
    private static function plainConnectionParameters(array $parameters): array
    {
        return array_intersect_key($parameters, array_flip(['driver', 'host', 'port', 'dbname', 'user', 'password', 'unix_socket', 'charset', 'serverVersion']));
    }

    private static function inPieces(string $content): StreamInterface
    {
        return new class (Utils::streamFor($content)) implements StreamInterface {
            use StreamDecoratorTrait;

            public function read($length): string
            {
                return $this->stream->read(min($length, 100));
            }
        };
    }
}
