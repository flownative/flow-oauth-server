<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

/**
 * Why a bearer token was not accepted, for the log only: the client always
 * gets the same challenge.
 */
enum AccessTokenRefusalReason: string
{
    case UNKNOWN = 'unknown token';
    case OTHER_RESOURCE = 'token of another resource';
    case EXPIRED = 'expired token';
    case REVOKED = 'revoked token';
    case GRANT_REVOKED = 'revoked grant';
}
