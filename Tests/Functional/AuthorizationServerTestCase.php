<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Functional;

use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\AuthorizationRequests;
use Flownative\OAuth2\Server\AuthorizationServerMiddleware;
use Flownative\OAuth2\Server\ConfiguredConsentPage;
use Flownative\OAuth2\Server\ConsentPageInterface;
use Flownative\OAuth2\Server\DatabasePlatform;
use Flownative\OAuth2\Server\ErrorRedirectPolicyInterface;
use Flownative\OAuth2\Server\Issuer;
use Flownative\OAuth2\Server\IssuerResolverInterface;
use Flownative\OAuth2\Server\RedirectErrorsOfApprovedClients;
use Flownative\OAuth2\Server\RequestHostIssuerResolver;
use GuzzleHttp\Psr7\ServerRequest;
use Neos\Flow\Configuration\ConfigurationManager;
use Neos\Flow\Http\ServerRequestAttributes;
use Neos\Flow\Persistence\Doctrine\Service as DoctrineService;
use Neos\Flow\Tests\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RuntimeException;

/**
 * Sends requests straight into the server's middleware, so that the tests
 * see the endpoints as a client does without the application's own chain.
 */
abstract class AuthorizationServerTestCase extends FunctionalTestCase
{
    protected const string ISSUER = 'https://server.test';
    protected const string REDIRECT_URI = 'https://client.test/callback';
    protected const string CLIENT_IP_ADDRESS = '192.0.2.1';
    protected const string CODE_VERIFIER = 'a-code-verifier-of-the-client-that-is-long-enough-1234567890';

    protected static $testablePersistenceEnabled = true;

    /**
     * @var array<string, object>
     */
    private array $instancesOfTheApplication = [];

    /**
     * An application replaces the resolver, the consent page and the error redirect policy; the package is tested with its own.
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->createTablesUnlessPresent();
        $instancesOfThePackage = [
            IssuerResolverInterface::class => new RequestHostIssuerResolver(),
            ConsentPageInterface::class => $this->objectManager->get(ConfiguredConsentPage::class),
            ErrorRedirectPolicyInterface::class => $this->objectManager->get(RedirectErrorsOfApprovedClients::class),
        ];
        foreach ($instancesOfThePackage as $objectName => $instance) {
            // An application that keeps the package's own needs no replacement, and a prototype cannot be replaced.
            if ($this->objectManager->getClassNameByObjectName($objectName) === $instance::class) {
                continue;
            }
            $this->instancesOfTheApplication[$objectName] = $this->objectManager->get($objectName);
            $this->objectManager->setInstance($objectName, $instance);
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->instancesOfTheApplication as $objectName => $instance) {
            $this->objectManager->setInstance($objectName, $instance);
        }
        parent::tearDown();
    }

    protected function databasePlatform(): DatabasePlatform
    {
        return DatabasePlatform::of($this->objectManager->get(Connection::class));
    }

    /**
     * SQL for a time the given seconds before the expression, for tests that move rows into the past.
     */
    protected function secondsBefore(string $expression, int $seconds): string
    {
        return match ($this->databasePlatform()) {
            DatabasePlatform::POSTGRESQL => sprintf("%s - interval '%d seconds'", $expression, $seconds),
            DatabasePlatform::MYSQL => sprintf('%s - INTERVAL %d SECOND', $expression, $seconds),
        };
    }

    /**
     * @return non-empty-string
     */
    protected function tokenPrefix(string $kind): string
    {
        $prefix = $this->objectManager->get(ConfigurationManager::class)->getConfiguration(ConfigurationManager::CONFIGURATION_TYPE_SETTINGS, 'Flownative.OAuth2.Server.tokenPrefixes.' . $kind);
        if (!is_string($prefix) || $prefix === '') {
            throw new RuntimeException('The server is configured without a token prefix', 1795110050);
        }
        return $prefix;
    }

    protected function issuer(): Issuer
    {
        return Issuer::fromString(self::ISSUER);
    }

    /**
     * @param array<string, string> $headers
     */
    protected function send(string $method, string $path, string|StreamInterface $body = '', array $headers = []): ResponseInterface
    {
        // REMOTE_ADDR is the ingress, the trusted proxies middleware has found the client behind it.
        $request = (new ServerRequest($method, self::ISSUER . $path, $headers, $body, '1.1', ['REMOTE_ADDR' => '10.0.0.1']))
            ->withAttribute(ServerRequestAttributes::CLIENT_IP, self::CLIENT_IP_ADDRESS);
        parse_str((string)parse_url($path, PHP_URL_QUERY), $query);
        return $this->objectManager->get(AuthorizationServerMiddleware::class)->process($request->withQueryParams($query), new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                throw new RuntimeException('The request passed the authorization server: ' . $request->getUri(), 1795083660);
            }
        });
    }

    /**
     * @param array<string, string> $parameters
     */
    protected function post(string $path, array $parameters): ResponseInterface
    {
        return $this->send('POST', $path, http_build_query($parameters), ['Content-Type' => 'application/x-www-form-urlencoded']);
    }

    /**
     * @return array<mixed>
     */
    protected static function json(ResponseInterface $response): array
    {
        $content = json_decode((string)$response->getBody(), true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($content);
        return $content;
    }

    /**
     * @param list<string> $redirectUris
     */
    protected function registerClient(array $redirectUris = [self::REDIRECT_URI]): string
    {
        $response = $this->send('POST', '/oauth/register', json_encode(['client_name' => 'Test client', 'redirect_uris' => $redirectUris], JSON_THROW_ON_ERROR), ['Content-Type' => 'application/json']);
        self::assertSame(201, $response->getStatusCode(), (string)$response->getBody());
        $clientIdentifier = self::json($response)['client_id'] ?? null;
        self::assertIsString($clientIdentifier);
        return $clientIdentifier;
    }

    /**
     * @param array<string, string> $overrides
     */
    protected function authorize(string $clientIdentifier, array $overrides = []): ResponseInterface
    {
        $parameters = array_merge([
            'response_type' => 'code',
            'client_id' => $clientIdentifier,
            'redirect_uri' => self::REDIRECT_URI,
            'code_challenge' => self::codeChallengeOf(self::CODE_VERIFIER),
            'code_challenge_method' => 'S256',
            'state' => 'state-of-the-client',
            'scope' => 'mcp',
        ], $overrides);
        return $this->send('GET', '/oauth/authorize?' . http_build_query(array_filter($parameters, static fn (string $value): bool => $value !== '')));
    }

    /**
     * Runs the authorization request through to the approved code.
     */
    protected function codeFor(string $clientIdentifier, string $subject = 'subject-1'): string
    {
        $response = $this->authorize($clientIdentifier);
        self::assertSame(302, $response->getStatusCode(), (string)$response->getBody());
        parse_str((string)parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $consentQuery);
        $requestIdentifier = $consentQuery['request'] ?? null;
        self::assertIsString($requestIdentifier);

        $approval = $this->objectManager->get(AuthorizationRequests::class)->approve($requestIdentifier, $this->issuer(), $subject);
        $parameters = self::queryOf($approval->redirectUri);
        self::assertSame('state-of-the-client', $parameters['state'] ?? null);
        self::assertSame(self::ISSUER, $parameters['iss'] ?? null);
        $code = $parameters['code'] ?? null;
        self::assertIsString($code);
        return $code;
    }

    protected function exchange(string $clientIdentifier, string $code, string $codeVerifier = self::CODE_VERIFIER): ResponseInterface
    {
        return $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientIdentifier,
            'code' => $code,
            'redirect_uri' => self::REDIRECT_URI,
            'code_verifier' => $codeVerifier,
        ]);
    }

    protected function refresh(string $clientIdentifier, string $refreshToken): ResponseInterface
    {
        return $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $clientIdentifier,
            'refresh_token' => $refreshToken,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    protected static function queryOf(string $uri): array
    {
        parse_str((string)parse_url($uri, PHP_URL_QUERY), $parameters);
        $result = [];
        foreach ($parameters as $name => $value) {
            $result[(string)$name] = $value;
        }
        return $result;
    }

    protected static function codeChallengeOf(string $codeVerifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
    }

    /**
     * An application may build the schema for its tests once and keep it.
     * Flow's own persistence manager drops every table after each test, so
     * then the package's migrations create them again.
     */
    private function createTablesUnlessPresent(): void
    {
        $connection = $this->objectManager->get(Connection::class);
        if ($connection->createSchemaManager()->tablesExist(['flownative_oauth2_server_grant'])) {
            return;
        }
        $versions = match (DatabasePlatform::of($connection)) {
            DatabasePlatform::POSTGRESQL => ['Version20261119101252'],
            DatabasePlatform::MYSQL => ['Version20261120190207', 'Version20261120201811', 'Version20261120203500'],
        };
        foreach ($versions as $version) {
            $this->objectManager->get(DoctrineService::class)->executeMigration('Neos\\Flow\\Persistence\\Doctrine\\Migrations\\' . $version);
        }
    }
}
