<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Functional;

use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\AccessTokenValidator;
use Flownative\OAuth2\Server\Issuer;
use Neos\Flow\Http\Helper\ResponseInformationHelper;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;
use Stringable;

class AuthorizationCodeFlowTest extends AuthorizationServerTestCase
{
    #[Test]
    public function aCodeWithPkceBuysAnAccessAndARefreshToken(): void
    {
        $clientIdentifier = $this->registerClient();

        $response = $this->exchange($clientIdentifier, $this->codeFor($clientIdentifier));

        self::assertSame(200, $response->getStatusCode(), (string)$response->getBody());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $tokens = self::json($response);
        self::assertSame('Bearer', $tokens['token_type']);
        self::assertSame('mcp', $tokens['scope']);
        self::assertEqualsWithDelta(3600, $tokens['expires_in'], 5, 'an access token lives an hour by default');
        self::assertIsString($tokens['access_token']);
        self::assertStringStartsWith($this->tokenPrefix('accessToken'), $tokens['access_token']);
        self::assertIsString($tokens['refresh_token']);
        self::assertStringStartsWith($this->tokenPrefix('refreshToken'), $tokens['refresh_token']);

        $validated = $this->objectManager->get(AccessTokenValidator::class)->validate($tokens['access_token'], $this->issuer());
        self::assertNotNull($validated);
        self::assertSame('subject-1', $validated->subject);
        self::assertSame($clientIdentifier, $validated->clientIdentifier);
        self::assertSame(['mcp'], $validated->scopes);
    }

    /**
     * Flow sends a body from where its stream stands, so an answer left at the end of its stream reaches the client empty.
     */
    #[Test]
    public function theTokenAnswersReachTheClientWhole(): void
    {
        $clientIdentifier = $this->registerClient();
        $exchanged = self::sentAnswerOf($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($exchanged['refresh_token'] ?? null);
        $refreshed = self::sentAnswerOf($this->refresh($clientIdentifier, $exchanged['refresh_token']));
        $refused = self::sentAnswerOf($this->exchange($clientIdentifier, 'no-code-at-all'));

        self::assertIsString($refreshed['access_token'] ?? null);
        self::assertSame('invalid_grant', $refused['error'] ?? null);
    }

    #[Test]
    public function aRefreshRotatesBothTokens(): void
    {
        $clientIdentifier = $this->registerClient();
        $first = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($first['refresh_token']);
        self::assertIsString($first['access_token']);

        $response = $this->refresh($clientIdentifier, $first['refresh_token']);

        self::assertSame(200, $response->getStatusCode(), (string)$response->getBody());
        $second = self::json($response);
        self::assertIsString($second['access_token']);
        self::assertNotSame($first['refresh_token'], $second['refresh_token']);
        self::assertNotSame($first['access_token'], $second['access_token']);
        $validator = $this->objectManager->get(AccessTokenValidator::class);
        self::assertNull($validator->validate($first['access_token'], $this->issuer()), 'the access token of a spent refresh token is revoked');
        self::assertNotNull($validator->validate($second['access_token'], $this->issuer()));
    }

    #[Test]
    public function aSpentRefreshTokenUsedAgainRevokesTheWholeGrant(): void
    {
        $clientIdentifier = $this->registerClient();
        $first = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($first['refresh_token']);
        $second = self::json($this->refresh($clientIdentifier, $first['refresh_token']));
        self::assertIsString($second['access_token']);
        self::assertIsString($second['refresh_token']);
        $this->backdateSpentRefreshTokens();

        $response = $this->refresh($clientIdentifier, $first['refresh_token']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
        self::assertNull($this->objectManager->get(AccessTokenValidator::class)->validate($second['access_token'], $this->issuer()), 'a second use shows a stolen token');
        self::assertSame('invalid_grant', self::json($this->refresh($clientIdentifier, $second['refresh_token']))['error']);
    }

    #[Test]
    public function aRefreshTokenRetriedAtOnceIsRefusedWithoutRevokingTheGrant(): void
    {
        $clientIdentifier = $this->registerClient();
        $first = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($first['refresh_token']);
        $second = self::json($this->refresh($clientIdentifier, $first['refresh_token']));
        self::assertIsString($second['access_token']);

        $response = $this->refresh($clientIdentifier, $first['refresh_token']);

        self::assertSame('invalid_grant', self::json($response)['error']);
        self::assertNotNull($this->objectManager->get(AccessTokenValidator::class)->validate($second['access_token'], $this->issuer()), 'a retry after a lost answer is no theft');
    }

    #[Test]
    public function aSpentRefreshTokenPresentedByAnotherClientLeavesTheGrant(): void
    {
        $clientIdentifier = $this->registerClient();
        $first = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($first['refresh_token']);
        $second = self::json($this->refresh($clientIdentifier, $first['refresh_token']));
        self::assertIsString($second['access_token']);
        $this->backdateSpentRefreshTokens();

        $response = $this->refresh($this->registerClient(), $first['refresh_token']);

        self::assertSame(self::json($this->refresh($clientIdentifier, 'oauth2_rt_unknown')), self::json($response), 'the answer tells nothing about the token');
        self::assertNotNull($this->objectManager->get(AccessTokenValidator::class)->validate($second['access_token'], $this->issuer()));
    }

    #[Test]
    public function aSpentCodeRevokesTheGrantOnlyForItsClientWithItsVerifier(): void
    {
        $clientIdentifier = $this->registerClient();
        $code = $this->codeFor($clientIdentifier);
        $tokens = self::json($this->exchange($clientIdentifier, $code));
        self::assertIsString($tokens['access_token']);
        $validator = $this->objectManager->get(AccessTokenValidator::class);

        $byAnotherClient = $this->exchange($this->registerClient(), $code);
        $withAWrongVerifier = $this->exchange($clientIdentifier, $code, str_repeat('x', 60));

        self::assertSame(self::json($this->exchange($clientIdentifier, 'unknown-code')), self::json($byAnotherClient), 'the answer tells nothing about the code');
        self::assertSame('invalid_grant', self::json($withAWrongVerifier)['error']);
        self::assertNotNull($validator->validate($tokens['access_token'], $this->issuer()));
        self::assertSame('invalid_grant', self::json($this->exchange($clientIdentifier, $code))['error']);
        self::assertNull($validator->validate($tokens['access_token'], $this->issuer()));
    }

    #[Test]
    public function aUsedCodeIsRefusedAndTakesItsTokensWithIt(): void
    {
        $clientIdentifier = $this->registerClient();
        $code = $this->codeFor($clientIdentifier);
        $tokens = self::json($this->exchange($clientIdentifier, $code));
        self::assertIsString($tokens['access_token']);

        $response = $this->exchange($clientIdentifier, $code);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
        self::assertNull($this->objectManager->get(AccessTokenValidator::class)->validate($tokens['access_token'], $this->issuer()));
    }

    #[Test]
    public function aWrongVerifierIsRefusedAndLeavesTheCodeUnspent(): void
    {
        $clientIdentifier = $this->registerClient();
        $code = $this->codeFor($clientIdentifier);

        $response = $this->exchange($clientIdentifier, $code, str_repeat('x', 60));

        self::assertSame('invalid_grant', self::json($response)['error']);
        self::assertSame(200, $this->exchange($clientIdentifier, $code)->getStatusCode());
    }

    #[Test]
    public function aRefusalIsLoggedWithTheClientButNeitherCodeNorVerifier(): void
    {
        $clientIdentifier = $this->registerClient();
        $code = $this->codeFor($clientIdentifier);
        $recorder = new class () extends AbstractLogger {
            public string $lines = '';

            public function log($level, string|Stringable $message, array $context = []): void
            {
                $this->lines .= (is_string($level) ? $level : '?') . ': ' . $message . "\n";
            }
        };
        $logger = $this->objectManager->get(LoggerInterface::class);
        $this->objectManager->setInstance(LoggerInterface::class, $recorder);
        try {
            $this->exchange($clientIdentifier, $code, str_repeat('x', 60));
        } finally {
            $this->objectManager->setInstance(LoggerInterface::class, $logger);
        }

        self::assertStringContainsString('info: OAuth request refused: POST /oauth/token 400 invalid_grant: ', $recorder->lines);
        self::assertStringContainsString(sprintf('(client %s, from %s)', $clientIdentifier, self::CLIENT_IP_ADDRESS), $recorder->lines);
        self::assertStringNotContainsString($code, $recorder->lines);
        self::assertStringNotContainsString(str_repeat('x', 60), $recorder->lines);
    }

    #[Test]
    public function aCodeOfAnotherClientIsRefused(): void
    {
        $clientIdentifier = $this->registerClient();
        $otherClientIdentifier = $this->registerClient();
        $code = $this->codeFor($clientIdentifier);

        $response = self::json($this->exchange($otherClientIdentifier, $code));

        self::assertSame('invalid_grant', $response['error']);
        self::assertSame('', $response['hint'] ?? '', 'the answer does not tell that the code exists');
        self::assertSame(200, $this->exchange($clientIdentifier, $code)->getStatusCode());
    }

    #[Test]
    public function aRevokedTokenIsRefused(): void
    {
        $clientIdentifier = $this->registerClient();
        $tokens = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($tokens['access_token']);
        self::assertIsString($tokens['refresh_token']);

        $response = $this->post('/oauth/revoke', ['token' => $tokens['access_token'], 'client_id' => $clientIdentifier]);

        self::assertSame(200, $response->getStatusCode());
        self::assertNull($this->objectManager->get(AccessTokenValidator::class)->validate($tokens['access_token'], $this->issuer()));
        self::assertSame('invalid_grant', self::json($this->refresh($clientIdentifier, $tokens['refresh_token']))['error'], 'revoking revokes the grant behind the token');
    }

    #[Test]
    public function anotherClientCannotRevokeAToken(): void
    {
        $clientIdentifier = $this->registerClient();
        $tokens = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($tokens['access_token']);

        $response = $this->post('/oauth/revoke', ['token' => $tokens['access_token'], 'client_id' => $this->registerClient()]);

        self::assertSame(200, $response->getStatusCode());
        self::assertNotNull($this->objectManager->get(AccessTokenValidator::class)->validate($tokens['access_token'], $this->issuer()));
    }

    #[Test]
    public function aTokenCountsOnlyForTheResourceOfItsIssuer(): void
    {
        $clientIdentifier = $this->registerClient();
        $tokens = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($tokens['access_token']);

        self::assertNull($this->objectManager->get(AccessTokenValidator::class)->validate($tokens['access_token'], Issuer::fromString('https://other.test')));
    }

    #[Test]
    public function anExpiredAccessTokenIsRefused(): void
    {
        $clientIdentifier = $this->registerClient();
        $tokens = self::json($this->exchange($clientIdentifier, $this->codeFor($clientIdentifier)));
        self::assertIsString($tokens['access_token']);

        $this->objectManager->get(Connection::class)->executeStatement('UPDATE flownative_oauth2_server_access_token SET expires_at = ' . $this->secondsBefore($this->databasePlatform()->now(), 1));

        self::assertNull($this->objectManager->get(AccessTokenValidator::class)->validate($tokens['access_token'], $this->issuer()));
    }

    private function backdateSpentRefreshTokens(): void
    {
        $this->objectManager->get(Connection::class)->executeStatement('UPDATE flownative_oauth2_server_refresh_token SET spent_at = ' . $this->secondsBefore('spent_at', 60) . ' WHERE spent_at IS NOT NULL');
    }

    /**
     * The answer as Flow puts it on the wire, which sends the body from where its stream stands.
     *
     * @return array<mixed>
     */
    private static function sentAnswerOf(ResponseInterface $response): array
    {
        // Flow derives the Content-Length from the size, whatever reaches the wire.
        $contentLength = $response->getBody()->getSize();
        ob_start();
        try {
            ResponseInformationHelper::sendStream($response->getBody());
        } finally {
            $sent = (string)ob_get_clean();
        }
        self::assertSame($contentLength, strlen($sent));
        $answer = json_decode($sent, true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($answer);

        return $answer;
    }
}
