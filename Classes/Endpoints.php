<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use Neos\Flow\Annotations as Flow;

/**
 * The paths the server answers under and the two metadata documents that
 * name them (RFC 8414, RFC 9728).
 */
#[Flow\Scope('singleton')]
class Endpoints
{
    private const string AUTHORIZATION_SERVER_METADATA_PATH = '/.well-known/oauth-authorization-server';
    private const string PROTECTED_RESOURCE_METADATA_PATH = '/.well-known/oauth-protected-resource';

    /**
     * @var array{authorization: string, token: string, registration: string, revocation: string}
     */
    #[Flow\InjectConfiguration(path: 'endpoints')]
    protected array $paths;

    #[Flow\InjectConfiguration(path: 'resourcePath')]
    protected string $resourcePath;

    /**
     * @var list<string>
     */
    #[Flow\InjectConfiguration(path: 'scopes.supported')]
    protected array $supportedScopes;

    /**
     * @var list<string>
     */
    #[Flow\InjectConfiguration(path: 'scopes.ofTheResource')]
    protected array $scopesOfTheResource;

    #[Flow\InjectConfiguration(path: 'registration.enabled')]
    protected bool $registrationEnabled;

    #[Flow\InjectConfiguration(path: 'clientMetadataDocuments.enabled')]
    protected bool $clientMetadataDocumentsEnabled;

    public function authorizationPath(): string
    {
        return $this->paths['authorization'];
    }

    public function tokenPath(): string
    {
        return $this->paths['token'];
    }

    public function registrationPath(): ?string
    {
        return $this->registrationEnabled ? $this->paths['registration'] : null;
    }

    public function revocationPath(): string
    {
        return $this->paths['revocation'];
    }

    public function isAuthorizationServerMetadataPath(string $path): bool
    {
        return $path === self::AUTHORIZATION_SERVER_METADATA_PATH;
    }

    public function isProtectedResourceMetadataPath(string $path): bool
    {
        return $path === self::PROTECTED_RESOURCE_METADATA_PATH || $path === self::PROTECTED_RESOURCE_METADATA_PATH . $this->resourcePath;
    }

    public function resourceOf(Issuer $issuer): string
    {
        return $issuer->uriOf($this->resourcePath);
    }

    /**
     * The WWW-Authenticate value a resource answers a request without a usable token with.
     */
    public function challengeFor(Issuer $issuer): string
    {
        return sprintf(
            'Bearer resource_metadata="%s", scope="%s"',
            $issuer->uriOf(self::PROTECTED_RESOURCE_METADATA_PATH . $this->resourcePath),
            implode(' ', $this->scopesOfTheResource)
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function authorizationServerMetadata(Issuer $issuer): array
    {
        $registrationPath = $this->registrationPath();
        return array_filter([
            'issuer' => $issuer->value,
            'authorization_endpoint' => $issuer->uriOf($this->authorizationPath()),
            'token_endpoint' => $issuer->uriOf($this->tokenPath()),
            'registration_endpoint' => $registrationPath !== null ? $issuer->uriOf($registrationPath) : null,
            'revocation_endpoint' => $issuer->uriOf($this->revocationPath()),
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['none'],
            'revocation_endpoint_auth_methods_supported' => ['none'],
            'client_id_metadata_document_supported' => $this->clientMetadataDocumentsEnabled,
            'authorization_response_iss_parameter_supported' => true,
            'scopes_supported' => $this->supportedScopes,
        ], static fn (mixed $value): bool => $value !== null);
    }

    /**
     * @return array<string, mixed>
     */
    public function protectedResourceMetadata(Issuer $issuer): array
    {
        return [
            'resource' => $this->resourceOf($issuer),
            'authorization_servers' => [$issuer->value],
            'scopes_supported' => $this->scopesOfTheResource,
            'bearer_methods_supported' => ['header'],
        ];
    }
}
