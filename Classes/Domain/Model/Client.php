<?php

namespace Flownative\OAuth2\Server\Domain\Model;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use Neos\Flow\Annotations\Entity;

/**
 * @Entity()
 */
final class Client implements ClientEntityInterface
{
    public function getIdentifier()
    {
        // TODO: Implement getIdentifier() method.
    }

    public function getName()
    {
        // TODO: Implement getName() method.
    }

    public function getRedirectUri()
    {
        // TODO: Implement getRedirectUri() method.
    }
}
