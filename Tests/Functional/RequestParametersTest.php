<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

class RequestParametersTest extends AuthorizationServerTestCase
{
    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function refusedAuthorizationParameters(): iterable
    {
        yield 'a NUL byte in the state' => [['state' => "a\0b"]];
        yield 'a state that is no UTF-8' => [['state' => "a\xffb"]];
        yield 'a control character in the scope' => [['scope' => "mcp\x1b"]];
        yield 'a long state' => [['state' => str_repeat('A', 1025)]];
        yield 'a long redirect URI' => [['redirect_uri' => self::REDIRECT_URI . '?' . str_repeat('a', 2048)]];
        yield 'a NUL byte in the client_id' => [['client_id' => "a\0b"]];
    }

    /**
     * @param array<string, string> $overrides
     */
    #[Test]
    #[DataProvider('refusedAuthorizationParameters')]
    public function anAuthorizationRequestWithBytesThatHaveNoPlaceInAParameterIsRefused(array $overrides): void
    {
        $response = $this->authorize($this->registerClient(), $overrides);

        self::assertSame(400, $response->getStatusCode());
        self::assertStringStartsWith('invalid_request', (string)$response->getBody());
        self::assertSame('', $response->getHeaderLine('Location'), 'nothing is sent back to the client');
    }

    #[Test]
    public function aStateOfAKilobyteIsAccepted(): void
    {
        self::assertSame(302, $this->authorize($this->registerClient(), ['state' => str_repeat('A', 1024)])->getStatusCode());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function refusedFormBodies(): iterable
    {
        yield 'a client_id at the token endpoint that is no UTF-8' => ['/oauth/token', 'grant_type=authorization_code&code=x&client_id=%FF'];
        yield 'a NUL byte at the token endpoint' => ['/oauth/token', 'grant_type=refresh_token&refresh_token=a%00b&client_id=c'];
        yield 'a parameter given as an array' => ['/oauth/token', 'grant_type[]=authorization_code&client_id=c'];
        yield 'a parameter name that is no UTF-8' => ['/oauth/token', 'grant_type=authorization_code&%FF=1'];
        yield 'a NUL byte at the revocation endpoint' => ['/oauth/revoke', 'token=x&client_id=a%00'];
    }

    #[Test]
    #[DataProvider('refusedFormBodies')]
    public function aFormWithBytesThatHaveNoPlaceInAParameterIsRefused(string $path, string $body): void
    {
        $response = $this->send('POST', $path, $body, ['Content-Type' => 'application/x-www-form-urlencoded']);

        self::assertSame(400, $response->getStatusCode(), (string)$response->getBody());
        self::assertSame('invalid_request', self::json($response)['error']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function refusedBasicCredentials(): iterable
    {
        yield 'a client_id that is no UTF-8' => ["\xff:"];
        yield 'a NUL byte in the client_id' => ["a\0b:"];
        yield 'a control character in the secret' => ["client:\x07"];
    }

    #[Test]
    #[DataProvider('refusedBasicCredentials')]
    public function basicCredentialsWithBytesThatHaveNoPlaceInAParameterAreRefused(string $credentials): void
    {
        $response = $this->send('POST', '/oauth/token', 'grant_type=refresh_token&refresh_token=x', ['Content-Type' => 'application/x-www-form-urlencoded', 'Authorization' => 'Basic ' . base64_encode($credentials)]);

        self::assertSame(400, $response->getStatusCode(), (string)$response->getBody());
        self::assertSame('invalid_request', self::json($response)['error']);
    }

    #[Test]
    public function aRegistrationWithAControlCharacterIsRefused(): void
    {
        $response = $this->send('POST', '/oauth/register', '{"client_name":"a\u0000b","redirect_uris":["https://client.test/callback"]}', ['Content-Type' => 'application/json']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_client_metadata', self::json($response)['error']);
    }
}
