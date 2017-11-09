<?php

namespace Flownative\OAuth2\Server\Domain\Model;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use Neos\Flow\Annotations\Identity;
use Neos\Flow\Annotations\Entity;
use Doctrine\ORM\Mapping as ORM;
use Neos\Flow\Annotations\Inject;
use Neos\Flow\Log\SystemLoggerInterface;

/**
 * @Entity
 */
final class Client implements ClientEntityInterface
{
    /**
     * @Identity
     * @ORM\Id
     * @var string
     */
    protected $identifier;

    /**
     * @var string
     */
    protected $name;

    /**
     * One of "client_credentials", "authorization_code"
     *
     * @var string
     */
    protected $grantType;

    /**
     * @var string
     */
    protected $hashedSecret = null;

    /**
     * @ORM\Column(nullable=true)
     * @var string
     */
    protected $redirectUri = null;

    /**
     * @Inject()
     * @var SystemLoggerInterface
     */
    protected $logger;

    /**
     * Client constructor.
     *
     * @param string $identifier
     * @param string $name
     * @param string $grantType
     * @param HashedSecret|null $hashedSecret
     * @param string|null $redirectUri
     */
    public function __construct($identifier, $name, $grantType, HashedSecret $hashedSecret = null, string $redirectUri = null)
    {
        $this->identifier = $identifier;
        $this->name = $name;
        $this->grantType = $grantType;
        $this->hashedSecret = $hashedSecret;
        $this->redirectUri = $redirectUri;
    }

    /**
     * @param string $secret
     * @return bool
     */
    public function validateSecret(string $secret): bool
    {
        if (is_string($this->hashedSecret)) {
            $this->hashedSecret = HashedSecret::fromHashedSecret($this->hashedSecret);
        }
        return $this->hashedSecret->validateClearTextSecret($secret);
    }

    /**
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @param string $name
     */
    public function setName(string $name)
    {
        $this->name = $name;
    }

    /**
     * @return string
     */
    public function getGrantType(): string
    {
        return $this->grantType;
    }

    /**
     * @param string $grantType
     */
    public function setGrantType(string $grantType)
    {
        $this->grantType = $grantType;
    }

    /**
     * @return string|null
     */
    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    /**
     * @param string $redirectUri
     */
    public function setRedirectUri(string $redirectUri)
    {
        $this->redirectUri = $redirectUri;
    }
}
