<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use DateInterval;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Flownative\OAuth2\Server\League\AuthorizationCodes;
use Flownative\OAuth2\Server\League\ValidatedAuthorizationRequest;
use Neos\Flow\Annotations as Flow;

/**
 * Validated authorization requests wait in a row for the subject's answer,
 * so that nothing lives in the memory of one process and a sign-in between
 * can come back to them. The application's consent page answers through
 * approve() or deny(); either spends the request.
 */
#[Flow\Scope('singleton')]
class AuthorizationRequests
{
    #[Flow\InjectConfiguration(path: 'lifetimes.authorizationRequest')]
    protected string $lifetime;

    public function __construct(
        private readonly Connection $connection,
        private readonly Grants $grants,
        private readonly AuthorizationCodes $authorizationCodes,
    ) {
    }

    public function store(Issuer $issuer, ValidatedAuthorizationRequest $request): PendingAuthorizationRequest
    {
        $pendingRequest = new PendingAuthorizationRequest(
            TokenSecret::generate(),
            $issuer,
            $request->client->identifier,
            $request->client->name,
            $request->redirectUri,
            $request->state,
            $request->scopes,
            $request->codeChallenge,
            $request->resource,
            (new DateTimeImmutable())->add(new DateInterval($this->lifetime)),
        );
        $this->connection->executeStatement(
            'INSERT INTO flownative_oauth2_server_authorization_request
                (request_id, issuer, client_id, client_name, redirect_uri, state, scopes, code_challenge, resource, created_at, expires_at)
             VALUES (:requestId, :issuer, :clientId, :clientName, :redirectUri, :state, :scopes, :codeChallenge, :resource, now(), :expiresAt)',
            [
                'requestId' => $pendingRequest->identifier,
                'issuer' => $issuer->value,
                'clientId' => $pendingRequest->clientIdentifier,
                'clientName' => $pendingRequest->clientName,
                'redirectUri' => $pendingRequest->redirectUri,
                'state' => $pendingRequest->state,
                'scopes' => json_encode($pendingRequest->scopes, JSON_THROW_ON_ERROR),
                'codeChallenge' => $pendingRequest->codeChallenge,
                'resource' => $pendingRequest->resource,
                'expiresAt' => $pendingRequest->expiresAt->format(DATE_ATOM),
            ]
        );
        return $pendingRequest;
    }

    /**
     * The request if it is still waiting under this issuer.
     */
    public function find(string $requestIdentifier, Issuer $issuer): ?PendingAuthorizationRequest
    {
        $row = $this->connection->fetchAssociative(
            'SELECT * FROM flownative_oauth2_server_authorization_request WHERE request_id = :requestId AND issuer = :issuer AND expires_at > now()',
            ['requestId' => $requestIdentifier, 'issuer' => $issuer->value]
        );
        return $row === false ? null : PendingAuthorizationRequest::fromRow($row);
    }

    /**
     * Creates the grant and a code for it; the application writes what it keeps
     * about the grant in the same transaction if it opened one around this call.
     *
     * @throws UnknownAuthorizationRequestException
     */
    public function approve(string $requestIdentifier, Issuer $issuer, string $subject): AuthorizationResponse
    {
        return $this->connection->transactional(function () use ($requestIdentifier, $issuer, $subject): AuthorizationResponse {
            $request = $this->spend($requestIdentifier, $issuer);
            $grantIdentifier = $this->grants->create($request, $subject);
            $code = $this->authorizationCodes->issue($grantIdentifier, $request->redirectUri, $request->codeChallenge);
            return new AuthorizationResponse($grantIdentifier, self::redirectUriWith($request->redirectUri, ['code' => $code, 'state' => $request->state, 'iss' => $issuer->value]));
        });
    }

    /**
     * @return string the address that tells the client access was denied
     * @throws UnknownAuthorizationRequestException
     */
    public function deny(string $requestIdentifier, Issuer $issuer): string
    {
        $request = $this->spend($requestIdentifier, $issuer);
        return self::redirectUriWith($request->redirectUri, ['error' => 'access_denied', 'state' => $request->state, 'iss' => $issuer->value]);
    }

    /**
     * @param array<string, string|null> $parameters
     */
    public static function redirectUriWith(string $redirectUri, array $parameters): string
    {
        $query = http_build_query(array_filter($parameters, static fn (?string $value): bool => $value !== null), '', '&', PHP_QUERY_RFC3986);
        return $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . $query;
    }

    /**
     * @throws UnknownAuthorizationRequestException
     */
    private function spend(string $requestIdentifier, Issuer $issuer): PendingAuthorizationRequest
    {
        $row = $this->connection->fetchAssociative(
            'DELETE FROM flownative_oauth2_server_authorization_request WHERE request_id = :requestId AND issuer = :issuer AND expires_at > now() RETURNING *',
            ['requestId' => $requestIdentifier, 'issuer' => $issuer->value]
        );
        if ($row === false) {
            throw new UnknownAuthorizationRequestException('The authorization request is unknown, expired or answered', 1795083658);
        }
        return PendingAuthorizationRequest::fromRow($row);
    }
}
