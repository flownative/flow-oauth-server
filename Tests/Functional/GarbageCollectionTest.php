<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Functional;

use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\AccessTokenValidator;
use Flownative\OAuth2\Server\Command\OAuthServerCommandController;
use Neos\Flow\Cli\CommandController;
use Neos\Flow\Cli\ConsoleOutput;
use PHPUnit\Framework\Attributes\Test;
use ReflectionProperty;
use Symfony\Component\Console\Output\BufferedOutput;

class GarbageCollectionTest extends AuthorizationServerTestCase
{
    #[Test]
    public function theGarbageCollectionRemovesWhatIsExpiredAndKeepsWhatServes(): void
    {
        $clientIdentifier = $this->registerClient();
        $tokens = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($tokens['access_token']);
        $connection = $this->objectManager->get(Connection::class);
        $now = $this->databasePlatform()->now();
        // More than one batch of the MySQL deletes.
        $expiredRequests = 1001;
        $rows = [];
        for ($row = 0; $row < $expiredRequests; $row++) {
            $rows[] = sprintf("('expired-%d', 'https://server.test', 'client', 'Client', 'https://client.test/callback', '[]', 'challenge', 'https://server.test/mcp', %s, %s)", $row, $this->secondsBefore($now, 120), $this->secondsBefore($now, 60));
        }
        $connection->executeStatement('INSERT INTO flownative_oauth2_server_authorization_request (request_id, issuer, client_id, client_name, redirect_uri, scopes, code_challenge, resource, created_at, expires_at) VALUES ' . implode(', ', $rows));
        $this->authorize($clientIdentifier);
        $connection->executeStatement("INSERT INTO flownative_oauth2_server_client (client_id, client_name, redirect_uris, origin, created_at, expires_at) VALUES
            ('https://stale.test/client', 'Stale', '[]', 'metadata_document', {$this->secondsBefore($now, 200000)}, {$this->secondsBefore($now, 100000)}),
            ('https://serving.test/client', 'Serving', '[]', 'metadata_document', {$this->secondsBefore($now, 2000)}, {$this->secondsBefore($now, 1000)})");

        $output = $this->collectGarbage();

        self::assertStringContainsString($expiredRequests . ' authorization requests removed', $output);
        self::assertStringContainsString('1 client metadata documents removed', $output);
        self::assertSame(1, (int)$connection->fetchOne('SELECT COUNT(*) FROM flownative_oauth2_server_authorization_request'), 'the waiting request stays');
        self::assertSame(['https://serving.test/client'], $connection->fetchFirstColumn("SELECT client_id FROM flownative_oauth2_server_client WHERE origin = 'metadata_document'"), 'a document serves a while past its lifetime');
        self::assertNotNull($this->objectManager->get(AccessTokenValidator::class)->validate($tokens['access_token'], $this->issuer()));
    }

    private function collectGarbage(): string
    {
        $commandController = $this->objectManager->get(OAuthServerCommandController::class);
        $bufferedOutput = new BufferedOutput();
        $consoleOutput = (new ReflectionProperty(CommandController::class, 'output'))->getValue($commandController);
        self::assertInstanceOf(ConsoleOutput::class, $consoleOutput);
        $consoleOutput->setOutput($bufferedOutput);
        $commandController->collectGarbageCommand();
        return $bufferedOutput->fetch();
    }
}
