<?php

namespace Flownative\OAuth2\Server;

use Flownative\OAuth2\Server\Domain\Repository\AccessTokenRepository;
use Flownative\OAuth2\Server\Domain\Repository\ServerConfigurationRepository;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\ResourceServer;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\Log\SystemLoggerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;

/**
 * An authentication provider which supports OAuth 2.0
 */
class OAuthAuthenticationProvider extends AbstractProvider
{
    /**
     * @Flow\Inject
     * @var Bootstrap
     */
    protected $bootstrap;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject(lazy=false)
     * @var AccessTokenRepository
     */
    protected $accessTokenRepository;

    /**
     * @Flow\Inject
     * @var ServerConfigurationRepository
     */
    protected $serverConfigurationRepository;

    /**
     * @Flow\Inject
     * @var SystemLoggerInterface
     */
    protected $logger;

    /**
     * Returns the class names of the tokens this provider can authenticate.
     *
     * @return array
     */
    public function getTokenClassNames()
    {
        return [OAuthAuthenticationToken::class];
    }

    /**
     * Checks the given token for validity and sets the token authentication status
     * accordingly (success, wrong credentials or no credentials given).
     *
     * @param \Neos\Flow\Security\Authentication\TokenInterface $authenticationToken The token to be authenticated
     * @return void
     * @throws \Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException
     * @throws \Exception
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!($authenticationToken instanceof OAuthAuthenticationToken)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1510154531570);
        }

        $serverPublicKey = $this->serverConfigurationRepository->findOneByConfigurationKey('publicKey');
        if ($serverPublicKey === null) {
            throw new OAuthServerException('Public key not found in OAuth server configuration.', 1510242131893);
        }

        $serverPublicKeyPathAndFilename = $this->saveKeyToFile($serverPublicKey);

        $resourceServer = new ResourceServer(
            $this->accessTokenRepository,
            $serverPublicKeyPathAndFilename
        );

        $requestHandler = $this->bootstrap->getActiveRequestHandler();
        if (!$requestHandler instanceof HttpRequestHandlerInterface) {
            throw new \RuntimeException('Unsupported request handler', 1510241866812);
        }

        try {
            // Workaround: PSR-7 hasHeader() should be case insensitive and return an array, but Flow is not and does not:
            $flowHttpRequest = $requestHandler->getHttpRequest();
            $psr7HttpRequest = new ServerRequest(
                $flowHttpRequest->getMethod(),
                $flowHttpRequest->getUri(),
                $flowHttpRequest->getHeaders()->getAll(),
                $flowHttpRequest->getBody()
            );

            $enrichedHttpRequest = $resourceServer->validateAuthenticatedRequest($psr7HttpRequest);

            $account = new Account();
            $account->setAccountIdentifier('oauth:' . $enrichedHttpRequest->getAttribute('oauth_client_id'));
            $roles = [];
            foreach ($this->options['authenticateRoles'] as $roleIdentifier) {
                $roles[] = $this->policyService->getRole($roleIdentifier);
            }
            $account->setRoles($roles);

            $authenticationToken->setAccount($account);
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        } catch (OAuthServerException $exception) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
        }
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
