<?php
namespace Flownative\OAuth2\Server;

use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Authentication\Token\SessionlessTokenInterface;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;

/**
 * Authentication token for OAuth server
 */
class OAuthAuthenticationToken extends AbstractToken implements SessionlessTokenInterface {

    /**
     * @param ActionRequest $actionRequest
     * @return bool|void
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        $httpRequest = $actionRequest->getHttpRequest();
        if (!$httpRequest->hasHeader('Authorization')) {
            return;
        }

        try {
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        } catch (InvalidAuthenticationStatusException $e) {
        }

    }
}
