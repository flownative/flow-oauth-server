<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\League;

use DateInterval;
use Flownative\OAuth2\Server\Endpoints;
use Flownative\OAuth2\Server\Grants;
use Flownative\OAuth2\Server\Issuer;
use League\OAuth2\Server\AuthorizationServer;
use Neos\Flow\Annotations as Flow;
use Psr\Log\LoggerInterface;

/**
 * Builds league's server for one issuer, with the package's own grants and
 * opaque tokens. The encryption key league asks for is never used, so each
 * server gets a random one.
 */
#[Flow\Scope('singleton')]
class AuthorizationServerFactory
{
    /**
     * @var array{accessToken: string, refreshToken: string}
     */
    #[Flow\InjectConfiguration(path: 'lifetimes')]
    protected array $lifetimes;

    #[Flow\InjectConfiguration(path: 'refreshTokenRetryGracePeriod')]
    protected int $refreshTokenRetryGracePeriod;

    #[Flow\InjectConfiguration(path: 'scopes.default')]
    protected string $defaultScope;

    #[Flow\Inject]
    protected ?LoggerInterface $logger = null;

    public function __construct(
        private readonly DbalClientRepository $clients,
        private readonly DbalAccessTokenRepository $accessTokens,
        private readonly DbalRefreshTokenRepository $refreshTokens,
        private readonly ConfiguredScopeRepository $scopes,
        private readonly AuthorizationCodes $authorizationCodes,
        private readonly Grants $grants,
        private readonly Endpoints $endpoints,
    ) {
    }

    public function create(Issuer $issuer): AuthorizationServer
    {
        $server = new AuthorizationServer($this->clients, $this->accessTokens, $this->scopes, new NoSigningKey(), bin2hex(random_bytes(32)), new OpaqueTokenResponse());
        $server->setDefaultScope($this->defaultScope);
        $accessTokenLifetime = new DateInterval($this->lifetimes['accessToken']);
        $server->enableGrantType($this->authorizationCodeGrant($issuer), $accessTokenLifetime);

        $refreshTokenGrant = new RotatingRefreshTokenGrant($this->refreshTokens, $this->accessTokens, $this->grants, $this->endpoints->resourceOf($issuer), $this->refreshTokenRetryGracePeriod, $this->logger);
        $refreshTokenGrant->setRefreshTokenTTL(new DateInterval($this->lifetimes['refreshToken']));
        $server->enableGrantType($refreshTokenGrant, $accessTokenLifetime);

        return $server;
    }

    public function authorizationCodeGrant(Issuer $issuer): PkceAuthorizationCodeGrant
    {
        $grant = new PkceAuthorizationCodeGrant($this->authorizationCodes, $this->grants, $this->endpoints->resourceOf($issuer));
        $grant->setClientRepository($this->clients);
        $grant->setScopeRepository($this->scopes);
        $grant->setDefaultScope($this->defaultScope);
        $grant->setRefreshTokenRepository($this->refreshTokens);
        $grant->setRefreshTokenTTL(new DateInterval($this->lifetimes['refreshToken']));
        return $grant;
    }
}
