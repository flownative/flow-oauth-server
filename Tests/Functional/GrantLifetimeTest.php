<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Functional;

use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\AccessTokenRefusalReason;
use Flownative\OAuth2\Server\AccessTokenValidator;
use PHPUnit\Framework\Attributes\Test;

class GrantLifetimeTest extends AuthorizationServerTestCase
{
    #[Test]
    public function aGrantWithoutALifetimeHasNoExpiry(): void
    {
        $clientIdentifier = $this->registerClient();
        $this->exchange($clientIdentifier, $this->codeFor($clientIdentifier));

        self::assertNull($this->objectManager->get(Connection::class)->fetchOne('SELECT expires_at FROM flownative_oauth2_server_grant'));
    }

    #[Test]
    public function anExpiredGrantRefusesTheRefreshAndTheAccessToken(): void
    {
        $this->setGrantLifetime('P30D');
        $clientIdentifier = $this->registerClient();
        $tokens = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($tokens['access_token']);
        self::assertIsString($tokens['refresh_token']);
        $validator = $this->objectManager->get(AccessTokenValidator::class);
        self::assertNotNull($validator->validate($tokens['access_token'], $this->issuer()), 'the grant is good until it expires');

        $this->objectManager->get(Connection::class)->executeStatement('UPDATE flownative_oauth2_server_grant SET expires_at = ' . $this->secondsBefore($this->databasePlatform()->now(), 1));

        self::assertNull($validator->validate($tokens['access_token'], $this->issuer()));
        self::assertSame(AccessTokenRefusalReason::GRANT_EXPIRED, $validator->refusalOf($tokens['access_token'], $this->issuer())->reason);
        self::assertSame('invalid_grant', self::json($this->refresh($clientIdentifier, $tokens['refresh_token']))['error']);
    }

    #[Test]
    public function aRefreshTokenNeverOutlivesItsGrant(): void
    {
        $this->setGrantLifetime('PT1H');
        $clientIdentifier = $this->registerClient();
        $first = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($first['refresh_token']);
        $connection = $this->objectManager->get(Connection::class);
        $query = 'SELECT COUNT(*) FROM flownative_oauth2_server_refresh_token t JOIN flownative_oauth2_server_grant g ON g.grant_id = t.grant_id WHERE t.expires_at = g.expires_at';
        self::assertSame(1, (int)$connection->fetchOne($query), 'the refresh token of 90 days is cut to the hour the grant has left');

        $second = self::json($this->refresh($clientIdentifier, $first['refresh_token']));

        self::assertArrayHasKey('refresh_token', $second);
        self::assertSame(2, (int)$connection->fetchOne($query), 'the rotated refresh token is cut as well');
    }
}
