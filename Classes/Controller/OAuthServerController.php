<?php

namespace Flownative\OAuth2\Server\Controller;

use Flownative\OAuth2\Server\Domain\Repository\AccessTokenRepository;
use Flownative\OAuth2\Server\Domain\Repository\ClientRepository;
use Flownative\OAuth2\Server\Domain\Repository\ScopeRepository;
use Flownative\OAuth2\Server\Domain\Repository\ServerConfigurationRepository;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Stream;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use Neos\Flow\Annotations\Inject;
use Neos\Flow\Mvc\Controller\ActionController;

final class OAuthServerController extends ActionController
{
    /**
     * @Inject(lazy=false)
     * @var ClientRepository
     */
    protected $clientRepository;

    /**
     * @Inject(lazy=false)
     * @var AccessTokenRepository
     */
    protected $accessTokenRepository;

    /**
     * @Inject(lazy=false)
     * @var ScopeRepository
     */
    protected $scopeRepository;

    /**
     * @Inject
     * @var ServerConfigurationRepository
     */
    protected $serverConfigurationRepository;

    /**
     * @var AuthorizationServer
     */
    protected $authorizationServer;

    /**
     * @var array
     */
    protected $supportedMediaTypes = ['application/json'];

    /**
     * @return void
     * @throws \Exception
     */
    public function initializeObject(): void
    {
        $encryptionKey = $this->serverConfigurationRepository->findOneByConfigurationKey('encryptionKey');
        if ($encryptionKey === null) {
            throw new \Flownative\OAuth2\Server\OAuthServerException('Encryption key not found in OAuth server configuration.', 1509978084514);
        }

        $privateKey = $this->serverConfigurationRepository->findOneByConfigurationKey('privateKey');
        if ($privateKey === null) {
            throw new \Flownative\OAuth2\Server\OAuthServerException('Private key not found in OAuth server configuration.', 1509978035365);
        }

        $privateKeyPathAndFilename = $this->saveKeyToFile($privateKey);

        $this->authorizationServer = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $privateKeyPathAndFilename,
            $encryptionKey->getConfigurationValue()
        );

        $this->authorizationServer->enableGrantType(
            new ClientCredentialsGrant(),
            new \DateInterval('PT1H')
        );
    }

    /**
     * @return string
     */
    public function accessTokenAction()
    {
        $response = new Response();

        $requestArguments = $this->request->getHttpRequest()->getArguments();
        if (isset($requestArguments['client_secret'])) {
            $requestArguments['client_secret'] = str_repeat('*', strlen($requestArguments['client_secret']));
        }
        $this->systemLogger->log('accessToken: Requested access token', LOG_INFO, $requestArguments);
        try {
            $response = $this->authorizationServer->respondToAccessTokenRequest(
                $this->request->getHttpRequest(),
                $response
            );
        } catch (OAuthServerException $exception)
        {
            $this->systemLogger->log(sprintf('accessToken: OAuthServerException: %s', $exception->getMessage()), LOG_INFO);
            $response = $exception->generateHttpResponse($response);
        } catch (\Exception $exception)
        {
            $body = new Stream('php://temp', 'r+');
            $body->write($exception->getMessage());
            $response = $response->withStatus(500)->withBody($body);
        }

        // Transfer the truly PSR-7 compatible response to the Flow HTTP response:
        $this->response->setStatus($response->getStatusCode());
        foreach ($response->getHeaders() as $headerName => $headerValues) {
            foreach ($headerValues as $headerValue) {
                $this->response->setHeader($headerName, $headerValue);
            }
        }

        $response->getBody()->rewind();
        $this->systemLogger->log(sprintf('accessToken: responding with HTTP status code %s', $response->getStatusCode()), LOG_DEBUG, $response->getBody()->getContents());

        $response->getBody()->rewind();
        return $response->getBody()->getContents();
    }

    /**
     * @param string $key
     * @return string
     */
    private function saveKeyToFile(string $key): string
    {
        $tmpDir = sys_get_temp_dir();
        $keyPath = $tmpDir . '/' . sha1($key) . '.key';

        if (!file_exists($keyPath) && !touch($keyPath)) {
            throw new \RuntimeException(sprintf('"%s" key file could not be created', $keyPath));
        }

        if (file_put_contents($keyPath, $key) === false) {
            throw new \RuntimeException(sprintf('Unable to write key file to temporary directory "%s"', $tmpDir));
        }

        if (chmod($keyPath, 0600) === false) {
            throw new \RuntimeException(sprintf('The key file "%s" file mode could not be changed with chmod to 600', $keyPath));
        }
        return 'file://' . $keyPath;
    }
}
