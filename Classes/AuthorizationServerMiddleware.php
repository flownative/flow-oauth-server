<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\Client\ClientRegistration;
use Flownative\OAuth2\Server\Client\InvalidClientMetadataException;
use Flownative\OAuth2\Server\League\AuthorizationServerFactory;
use Flownative\OAuth2\Server\League\DbalClientRepository;
use Flownative\OAuth2\Server\League\ReusedCredentialException;
use GuzzleHttp\Psr7\Response;
use JsonException;
use League\OAuth2\Server\Exception\OAuthServerException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\ServerRequestAttributes;
use Neos\Flow\Log\Utility\LogEnvironment;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

/**
 * Answers the endpoints of the authorization server before Flow routes the
 * request: they are public, speak OAuth's own formats and need neither a
 * session nor a CSRF token. Everything else passes through.
 */
class AuthorizationServerMiddleware implements MiddlewareInterface
{
    private const int MAXIMUM_BODY_BYTES = 16384;
    private const int MAXIMUM_PARAMETER_BYTES = 2048;
    private const int MAXIMUM_STATE_BYTES = 1024;

    #[Flow\InjectConfiguration(path: 'enabled')]
    protected bool $enabled;

    #[Flow\Inject]
    protected ?LoggerInterface $logger = null;

    public function __construct(
        private readonly Endpoints $endpoints,
        private readonly IssuerResolverInterface $issuerResolver,
        private readonly AuthorizationServerFactory $serverFactory,
        private readonly AuthorizationRequests $authorizationRequests,
        private readonly ConsentPageInterface $consentPage,
        private readonly ErrorRedirectPolicyInterface $errorRedirectPolicy,
        private readonly ClientRegistration $clientRegistration,
        private readonly Grants $grants,
        private readonly DbalClientRepository $clients,
        private readonly Connection $connection,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $next): ResponseInterface
    {
        if (!$this->enabled) {
            return $next->handle($request);
        }
        $path = $request->getUri()->getPath();
        $method = $request->getMethod();
        $endpoint = match (true) {
            $method === 'GET' && $this->endpoints->isAuthorizationServerMetadataPath($path) => $this->authorizationServerMetadata(...),
            $method === 'GET' && $this->endpoints->isProtectedResourceMetadataPath($path) => $this->protectedResourceMetadata(...),
            $method === 'GET' && $path === $this->endpoints->authorizationPath() => $this->authorize(...),
            $method === 'POST' && $path === $this->endpoints->tokenPath() => $this->token(...),
            $method === 'POST' && $path === $this->endpoints->registrationPath() => $this->register(...),
            $method === 'POST' && $path === $this->endpoints->revocationPath() => $this->revoke(...),
            default => null,
        };
        if ($endpoint === null) {
            return $next->handle($request);
        }
        try {
            $issuer = $this->issuerResolver->issuerFor($request);
        } catch (UnknownIssuerException) {
            return $next->handle($request);
        }
        $response = $endpoint($request, $issuer);
        if ($response->getStatusCode() >= 400 && $path !== $this->endpoints->authorizationPath()) {
            $this->refused($request, $response, self::reasonInTheBodyOf($response));
        }
        // League writes its answers into the body and leaves the stream at the end, where Flow would start sending.
        if ($response->getBody()->isSeekable()) {
            $response->getBody()->rewind();
        }

        return $response;
    }

    private function authorizationServerMetadata(ServerRequestInterface $request, Issuer $issuer): ResponseInterface
    {
        return self::json(200, $this->endpoints->authorizationServerMetadata($issuer), ['Cache-Control' => 'private, max-age=3600']);
    }

    private function protectedResourceMetadata(ServerRequestInterface $request, Issuer $issuer): ResponseInterface
    {
        return self::json(200, $this->endpoints->protectedResourceMetadata($issuer), ['Cache-Control' => 'private, max-age=3600']);
    }

    private function authorize(ServerRequestInterface $request, Issuer $issuer): ResponseInterface
    {
        $problem = self::problemWithParameters($request->getQueryParams());
        if ($problem !== null) {
            return $this->refused($request, $this->consentPage->refusal('invalid_request', $problem), 'invalid_request: ' . $problem);
        }
        $this->learnClientOf($request, $request->getQueryParams());
        try {
            $validatedRequest = $this->serverFactory->authorizationCodeGrant($issuer)->validateRequest($request);
        } catch (OAuthServerException $exception) {
            $redirectUri = $exception->getRedirectUri();
            $clientIdentifier = $request->getQueryParams()['client_id'] ?? null;
            if ($redirectUri === null || !is_string($clientIdentifier) || !$this->errorRedirectPolicy->mayRedirectErrors($issuer, $clientIdentifier)) {
                return $this->refused($request, $this->consentPage->refusal($exception->getErrorType(), $exception->getHint() ?? $exception->getMessage()), self::reasonOf($exception));
            }
            $state = $request->getQueryParams()['state'] ?? null;
            return $this->refused($request, new Response(302, ['Location' => AuthorizationRequests::redirectUriWith($redirectUri, [
                'error' => $exception->getErrorType(),
                'error_description' => $exception->getHint() ?? $exception->getMessage(),
                'state' => is_string($state) ? $state : null,
                'iss' => $issuer->value,
            ])]), self::reasonOf($exception) . ', sent back to the client');
        }
        $pendingRequest = $this->authorizationRequests->store($issuer, $validatedRequest);
        return new Response(302, ['Location' => $this->consentPage->uriFor($pendingRequest), 'Cache-Control' => 'no-store']);
    }

    private function token(ServerRequestInterface $request, Issuer $issuer): ResponseInterface
    {
        $parameters = self::formParameters($request);
        if ($parameters === null) {
            return self::tooLarge();
        }
        $basicCredentials = self::basicCredentials($request);
        $problem = self::problemWithParameters([...$parameters, ...$basicCredentials ?? []]);
        if ($problem !== null) {
            return self::json(400, ['error' => 'invalid_request', 'error_description' => $problem]);
        }
        // Fetched before the transaction, which holds no connection open meanwhile and whose rollback keeps the client.
        // The body's client_id wins over the header's, as league reads them.
        $this->learnClientOf($request, [...$basicCredentials ?? [], ...$parameters]);
        $request = $request->withParsedBody($parameters);
        $server = $this->serverFactory->create($issuer);
        try {
            return $this->connection->transactional(static fn (): ResponseInterface => $server->respondToAccessTokenRequest($request, new Response()));
        } catch (ReusedCredentialException $exception) {
            $this->grants->revoke($exception->grantIdentifier());
            $this->logger?->warning(sprintf('A code or refresh token of grant %s was presented a second time; the grant is revoked', $exception->grantIdentifier()), LogEnvironment::fromMethodName(__METHOD__));
            return $exception->generateHttpResponse(new Response())->withHeader('Cache-Control', 'no-store');
        } catch (OAuthServerException $exception) {
            return $exception->generateHttpResponse(new Response())->withHeader('Cache-Control', 'no-store');
        }
    }

    private function register(ServerRequestInterface $request, Issuer $issuer): ResponseInterface
    {
        $body = self::body($request);
        if ($body === null) {
            return self::tooLarge();
        }
        try {
            $metadata = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return self::json(400, ['error' => 'invalid_client_metadata', 'error_description' => 'The body is no JSON object']);
        }
        if (!is_array($metadata)) {
            return self::json(400, ['error' => 'invalid_client_metadata', 'error_description' => 'The body is no JSON object']);
        }
        if (self::containsControlCharacters($metadata)) {
            return self::json(400, ['error' => 'invalid_client_metadata', 'error_description' => 'The metadata contains control characters']);
        }
        $clientIpAddress = $request->getAttribute(ServerRequestAttributes::CLIENT_IP);
        $registeredFrom = is_string($clientIpAddress) ? $clientIpAddress : '';
        try {
            return self::json(201, $this->clientRegistration->register($metadata, $registeredFrom));
        } catch (InvalidClientMetadataException $exception) {
            return self::json(400, ['error' => $exception->error, 'error_description' => $exception->getMessage()]);
        }
    }

    private function revoke(ServerRequestInterface $request, Issuer $issuer): ResponseInterface
    {
        $parameters = self::formParameters($request);
        if ($parameters === null) {
            return self::tooLarge();
        }
        $problem = self::problemWithParameters($parameters);
        if ($problem !== null) {
            return self::json(400, ['error' => 'invalid_request', 'error_description' => $problem]);
        }
        $token = $parameters['token'] ?? null;
        $clientIdentifier = $parameters['client_id'] ?? null;
        if (!is_string($token) || $token === '' || !is_string($clientIdentifier) || $clientIdentifier === '') {
            return self::json(400, ['error' => 'invalid_request', 'error_description' => 'token and client_id are required']);
        }
        // An unknown token or one of another client is answered alike, so that the endpoint tells nothing about tokens.
        $this->grants->revokeByToken($token, $clientIdentifier);
        return new Response(200, ['Cache-Control' => 'no-store']);
    }

    /**
     * One info line per refused request, so that a client failing to connect
     * shows why; it names the client, never a code, a verifier or a secret.
     */
    private function refused(ServerRequestInterface $request, ResponseInterface $response, string $reason): ResponseInterface
    {
        $parameters = [...$request->getQueryParams(), ...$request->getMethod() === 'POST' ? self::formParameters($request) ?? [] : []];
        $clientIdentifier = $parameters['client_id'] ?? self::basicCredentials($request)['client_id'] ?? null;
        // A line with bytes that are no UTF-8 would reach the log empty.
        if (!is_string($clientIdentifier) || strlen($clientIdentifier) > 256 || self::containsControlCharacters($clientIdentifier)) {
            $clientIdentifier = null;
        }
        $remoteAddress = $request->getAttribute(ServerRequestAttributes::CLIENT_IP);
        $this->logger?->info(sprintf(
            'OAuth request refused: %s %s %d %s (client %s, from %s)',
            $request->getMethod(),
            $request->getUri()->getPath(),
            $response->getStatusCode(),
            $reason,
            is_string($clientIdentifier) ? $clientIdentifier : '-',
            is_string($remoteAddress) ? $remoteAddress : '-',
        ), LogEnvironment::fromMethodName(__METHOD__));

        return $response;
    }

    private static function reasonOf(OAuthServerException $exception): string
    {
        return $exception->getErrorType() . ': ' . $exception->getMessage() . ($exception->getHint() === null ? '' : ' (' . $exception->getHint() . ')');
    }

    /**
     * The error and its description from an OAuth answer in JSON.
     */
    private static function reasonInTheBodyOf(ResponseInterface $response): string
    {
        try {
            $content = json_decode((string)$response->getBody(), true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $content = null;
        }
        $error = is_array($content) ? $content['error'] ?? null : null;
        $description = is_array($content) ? $content['error_description'] ?? null : null;
        $hint = is_array($content) ? $content['hint'] ?? null : null;

        return (is_string($error) ? $error : 'refused') . (is_string($description) ? ': ' . $description : '') . (is_string($hint) ? ' (' . $hint . ')' : '');
    }

    /**
     * @param array<mixed> $parameters
     */
    private function learnClientOf(ServerRequestInterface $request, array $parameters): void
    {
        $clientIdentifier = $parameters['client_id'] ?? null;
        $sourceAddress = $request->getAttribute(ServerRequestAttributes::CLIENT_IP);
        if (is_string($clientIdentifier)) {
            $this->clients->learnFromMetadataDocument($clientIdentifier, is_string($sourceAddress) ? $sourceAddress : '');
        }
    }

    /**
     * The client credentials of an Authorization header as league reads them.
     *
     * @return array{client_id: string, client_secret: string}|null
     */
    private static function basicCredentials(ServerRequestInterface $request): ?array
    {
        $header = $request->getHeaderLine('Authorization');
        $decoded = stripos($header, 'Basic ') === 0 ? base64_decode(substr($header, 6), true) : false;
        if ($decoded === false || !str_contains($decoded, ':')) {
            return null;
        }
        [$clientIdentifier, $clientSecret] = explode(':', $decoded, 2);
        return ['client_id' => $clientIdentifier, 'client_secret' => $clientSecret];
    }

    /**
     * Bytes the database refuses or that have no place in a parameter would
     * otherwise surface as a database error instead of an OAuth one.
     *
     * @param array<mixed> $parameters
     */
    private static function problemWithParameters(array $parameters): ?string
    {
        foreach ($parameters as $name => $value) {
            $name = (string)$name;
            if (strlen($name) > 64 || self::containsControlCharacters($name)) {
                return 'A parameter name is too long, no UTF-8 or contains control characters';
            }
            $maximumBytes = $name === 'state' ? self::MAXIMUM_STATE_BYTES : self::MAXIMUM_PARAMETER_BYTES;
            if (!is_string($value)) {
                return sprintf('The parameter %s must be given once, as a string', $name);
            }
            if (strlen($value) > $maximumBytes) {
                return sprintf('The parameter %s is longer than %d bytes', $name, $maximumBytes);
            }
            if (self::containsControlCharacters($value)) {
                return sprintf('The parameter %s is no UTF-8 or contains control characters', $name);
            }
        }
        return null;
    }

    /**
     * True also for bytes that are no UTF-8, in a string or anywhere in an array.
     */
    private static function containsControlCharacters(mixed $value): bool
    {
        if (is_array($value)) {
            foreach ($value as $key => $item) {
                if (self::containsControlCharacters((string)$key) || self::containsControlCharacters($item)) {
                    return true;
                }
            }
            return false;
        }
        return is_string($value) && (!mb_check_encoding($value, 'UTF-8') || preg_match('/\p{Cc}/u', $value) === 1);
    }

    /**
     * @return array<string, mixed>|null null if the body is too large
     */
    private static function formParameters(ServerRequestInterface $request): ?array
    {
        $body = self::body($request);
        if ($body === null) {
            return null;
        }
        parse_str($body, $parameters);
        $result = [];
        foreach ($parameters as $name => $value) {
            $result[(string)$name] = $value;
        }
        return $result;
    }

    /**
     * @return string|null null if the body is too large
     */
    private static function body(ServerRequestInterface $request): ?string
    {
        $body = $request->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }
        $content = '';
        while (!$body->eof()) {
            $chunk = $body->read(self::MAXIMUM_BODY_BYTES + 1 - strlen($content));
            if ($chunk === '') {
                break;
            }
            $content .= $chunk;
            if (strlen($content) > self::MAXIMUM_BODY_BYTES) {
                return null;
            }
        }
        return $content;
    }

    private static function tooLarge(): ResponseInterface
    {
        return self::json(413, ['error' => 'invalid_request', 'error_description' => 'The body is too large']);
    }

    /**
     * @param array<string, mixed> $content
     * @param array<string, string> $headers
     */
    private static function json(int $status, array $content, array $headers = []): ResponseInterface
    {
        return new Response($status, ['Content-Type' => 'application/json; charset=UTF-8', 'Cache-Control' => 'no-store', ...$headers], json_encode($content, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }
}
