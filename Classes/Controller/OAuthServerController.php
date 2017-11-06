<?php

namespace Flownative\OAuth2\Server\Controller;

use Flownative\OAuth2\Server\Domain\Repository\AccessTokenRepository;
use Flownative\OAuth2\Server\Domain\Repository\ClientRepository;
use Flownative\OAuth2\Server\Domain\Repository\ScopeRepository;
use Flownative\OAuth2\Server\Domain\Repository\ServerConfigurationRepository;
use GuzzleHttp\Psr7\Stream;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use Neos\Flow\Annotations\Inject;
use Neos\Flow\Mvc\Controller\ActionController;

final class OAuthServerController extends ActionController
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
     * @var AuthorizationServer
     */
    private $server;

    /**
     * @return void
     */
    public function initializeObject(): void
    {
        $privateKey = $this->serverConfigurationRepository->findOneByKey('privateKey');
        if ($privateKey === null) {
            throw new \Flownative\OAuth2\Server\OAuthServerException('Private key not found in OAuth server configuration.', 1509978035365);
        }

        $encryptionKey = $this->serverConfigurationRepository->findOneByKey('encryptionKey');
        if ($encryptionKey === null) {
            throw new \Flownative\OAuth2\Server\OAuthServerException('Encryption key not found in OAuth server configuration.', 1509978084514);
        }

        $this->server = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $privateKey,
            $encryptionKey
        );

        $this->server->enableGrantType(
            new ClientCredentialsGrant(),
            new \DateInterval('PT1H')
        );
    }

    /**
     * @return void
     */
    public function accessTokenAction(): void
    {
        try {
            $this->server->respondToAccessTokenRequest(
                $this->request->getHttpRequest(),
                $this->response
            );
        } catch (OAuthServerException $exception)
        {
            $this->response = $exception->generateHttpResponse($this->response);
        } catch (\Exception $exception)
        {
            $body = new Stream('php://temp', 'r+');
            $body->write($exception->getMessage());
            $this->response = $this->response->withStatus(500)->withBody($body);
        }
    }
}
