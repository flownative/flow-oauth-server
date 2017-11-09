<?php

namespace Flownative\OAuth2\Server\Command;

use Flownative\OAuth2\Server\Domain\Model\Client;
use Flownative\OAuth2\Server\Domain\Model\HashedSecret;
use Flownative\OAuth2\Server\Domain\Model\ServerConfiguration;
use Flownative\OAuth2\Server\Domain\Repository\AccessTokenRepository;
use Flownative\OAuth2\Server\Domain\Repository\ClientRepository;
use Flownative\OAuth2\Server\Domain\Repository\ScopeRepository;
use Flownative\OAuth2\Server\Domain\Repository\ServerConfigurationRepository;
use Neos\Flow\Annotations\Inject;
use Neos\Flow\Cli\CommandController;

final class OAuthServerCommandController extends CommandController
{
    /**
     * @Inject()
     * @var ClientRepository
     */
    protected $clientRepository;

    /**
     * @Inject()
     * @var AccessTokenRepository
     */
    protected $accessTokenRepository;

    /**
     * @Inject()
     * @var ScopeRepository
     */
    protected $scopeRepository;

    /**
     * @Inject()
     * @var ServerConfigurationRepository
     */
    protected $serverConfigurationRepository;

    /**
     * Generate server keys
     *
     * This command generates the OAuth server private / public key pair and an encryption key and stores them in the
     * database.
     */
    public function generateServerKeysCommand()
    {
        $encryptionKey = base64_encode(random_bytes(32));

        $serverConfiguration = $this->serverConfigurationRepository->findOneByConfigurationKey('encryptionKey');
        if ($serverConfiguration === null) {
            $this->serverConfigurationRepository->add(new ServerConfiguration('encryptionKey', $encryptionKey));
        } else {
            $serverConfiguration->setConfigurationValue($encryptionKey);
            $this->serverConfigurationRepository->update($serverConfiguration);
        }

        list($privateKey, $publicKey, $consoleOutput) = $this->generateKeyPair();

        $serverConfiguration = $this->serverConfigurationRepository->findOneByConfigurationKey('privateKey');
        if ($serverConfiguration === null) {
            $this->serverConfigurationRepository->add(new ServerConfiguration('privateKey', $privateKey));
        } else {
            $serverConfiguration->setConfigurationValue($privateKey);
            $this->serverConfigurationRepository->update($serverConfiguration);
        }

        $serverConfiguration = $this->serverConfigurationRepository->findOneByConfigurationKey('publicKey');
        if ($serverConfiguration === null) {
            $this->serverConfigurationRepository->add(new ServerConfiguration('publicKey', $publicKey));
        } else {
            $serverConfiguration->setConfigurationValue($publicKey);
            $this->serverConfigurationRepository->update($serverConfiguration);
        }

        $this->outputLine('<success>Generated a new key pair and stored it in the database.</success>');
    }

    /**
     * Create client credentials
     *
     * Creates client credentials (ie., basically an "account" which can authenticate via Client Credentials Grant)
     *
     * @param string $identifier The client identifier
     * @param string $name Name of the machine / system / person owning the new client credentials
     * @param string|null $secret
     */
    public function createClientCredentialsCommand(string $identifier, string $name, string $secret = null)
    {
        if ($this->clientRepository->findOneByIdentifier($identifier) !== null) {
            $this->outputLine('<error>A client with this identifier already exists.</error>');
            $this->quit(1);
        }

        if ($secret === null) {
            $secret = base64_encode(random_bytes(30));
        }

        $hashedSecret = HashedSecret::fromClearTextSecret($secret);

        $client = new Client($identifier, $name, 'client_credentials', $hashedSecret);
        $this->clientRepository->add($client);

        $this->outputLine('Client credentials created. Secret: <b>%s</b>', [$secret]);
    }

    /**
     * List clients
     *
     * Lists existing clients
     */
    public function listClientsCommand()
    {
        $rows = [];
        foreach ($this->clientRepository->findAll() as $client) {
            /** @var Client $client */
            $rows[] = [
                $client->getIdentifier(),
                $client->getName(),
                $client->getGrantType()
            ];
        }

        $this->output->outputTable(
            $rows,
            ['Identifier', 'Name', 'Grant Type']
        );
    }

    /**
     * Remove client
     *
     * Removes an existing client
     *
     * @param string $identifier The client identifier
     */
    public function removeClientCommand(string $identifier)
    {
        $client = $this->clientRepository->findOneByIdentifier($identifier);
        if ($client === null) {
            $this->outputLine('<error>Client not found.</error>');
            $this->quit(1);
        }

        $this->clientRepository->remove($client);

        $this->outputLine('Client removed.');
    }

    /**
     * Generates a key pair for the OAuth server
     *
     * @return array
     */
    protected function generateKeyPair()
    {
        $filename = 'oauth_server_rsa';
        if (file_exists('/tmp/' . $filename . '.pub')) {
            unlink('/tmp/' . $filename . '.pub');
        }
        if (file_exists('/tmp/' . $filename)) {
            unlink('/tmp/' . $filename);
        }

        $command = 'openssl genrsa -out /tmp/' . $filename . ' 4096 2>/dev/null';
        exec($command, $output, $exitCode);
        if ($exitCode !== 0) {
            $consoleOutput = trim(implode("\n", $output), "\n");
            return [false, false, $consoleOutput];
        }

        $command = 'openssl rsa -in /tmp/' . $filename . ' -pubout -out /tmp/' . $filename . '.pub 2>/dev/null';
        exec($command, $output, $exitCode);
        if ($exitCode !== 0) {
            $consoleOutput = trim(implode("\n", $output), "\n");
            return [false, false, $consoleOutput];
        }

        $privateKey = file_get_contents('/tmp/' . $filename);
        $publicKey = file_get_contents('/tmp/' . $filename . '.pub');
        unlink('/tmp/' . $filename);
        unlink('/tmp/' . $filename . '.pub');

        return [trim($privateKey), trim($publicKey), ''];
    }
}
