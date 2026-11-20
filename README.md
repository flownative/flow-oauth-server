[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg)](http://opensource.org/licenses/MIT)
[![Packagist](https://img.shields.io/packagist/v/flownative/oauth2-server.svg)](https://packagist.org/packages/flownative/oauth2-server)
[![Maintenance level: Love](https://img.shields.io/badge/maintenance-%E2%99%A1%E2%99%A1%E2%99%A1-ff69b4.svg)](https://www.flownative.com/en/products/open-source.html)

# OAuth 2.1 Authorization Server for Flow Framework

This [Flow](https://flow.neos.io) package turns a Flow application into
an OAuth 2.1 authorization server, built on
[league/oauth2-server](https://oauth2.thephpleague.com/). It was written
for applications that let other programs, such as AI agents speaking the
Model Context Protocol, act on behalf of their users.

It supports:

- the authorization code grant with PKCE (S256 only),
- refresh tokens which are replaced on every use,
- opaque access and refresh tokens, stored only as digests,
- client metadata documents: a client names an https URL as its
  `client_id`, and the server fetches its metadata from there,
- dynamic client registration (RFC 7591) for public clients,
- token revocation (RFC 7009),
- authorization server metadata (RFC 8414) and protected resource
  metadata (RFC 9728).

A middleware answers the endpoints before Flow's routing. The pages a
person sees, the consent page above all, stay with the application.

## Requirements

- PHP 8.4 or 8.5 with the curl and mbstring extensions
- Flow 9
- PostgreSQL, MySQL 8.0.17 or later, or MariaDB 10.6 or later

The package brings its tables as Doctrine migrations for PostgreSQL
(`Migrations/Postgresql`) and for MySQL and MariaDB (`Migrations/Mysql`);
`./flow doctrine:migrate` runs the ones of the configured database.
On MySQL and MariaDB the tables store their timestamps in UTC, and
subjects can be at most 768 characters long, the longest key an index
takes. MySQL older than 8.0.17 ignores the CHECK constraints of the
tables and lacks `utf8mb4_0900_bin`, the binary collation without
padding which makes an identifier match only itself. Client identifiers
are limited to 768 characters on every database: a longer one is
answered as an unknown client.

## Installation

```bash
composer require flownative/oauth2-server
./flow doctrine:migrate
```

Flow 9 still requires `psr/http-message` 1.x, while league/oauth2-server
asks for 2.0. Until Flow allows 2.0
([neos/flow-development-collection#3665](https://github.com/neos/flow-development-collection/issues/3665)),
add an alias to the `require` section of your root `composer.json`:

```json
"psr/http-message": "1.1 as 2.0"
```

Expired authorization requests, codes and tokens, stale client metadata
documents and registered clients which never got a grant are removed by
the garbage collection. Run it regularly, for example once an hour:

```bash
./flow oauthserver:collectgarbage
```

## Configuration

The server is off by default. Turn it on once the application provides
its consent page and, where needed, its issuer resolver (see below):

```yaml
Flownative:
  OAuth2:
    Server:
      enabled: true
```

All settings, with their defaults, are in
[Configuration/Settings.yaml](Configuration/Settings.yaml). The most
important ones:

| Setting | Default | Meaning |
|---|---|---|
| `endpoints.*` | `/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/oauth/revoke` | Paths of the endpoints below the issuer |
| `resourcePath` | `/mcp` | The protected resource tokens are bound to, below the issuer |
| `consentPagePath` | `/oauth/consent` | Where the default consent page sends a validated request |
| `lifetimes.*` | `PT10M`, `PT1M`, `PT1H`, `P90D` | ISO 8601 durations of authorization requests, codes, access tokens and refresh tokens |
| `refreshTokenRetryGracePeriod` | `3` | Seconds in which a client presenting a spent refresh token again gets `invalid_grant` without its grant being revoked |
| `tokenPrefixes.*` | `oauth2_at_`, `oauth2_rt_` | Prefixes which let secret scanners recognize a token |
| `scopes.*` | `mcp`, `offline_access` | Supported scopes, the default scope and the scopes of the resource |
| `clientMetadataDocuments.*` | enabled | Size limit, timeout, cache lifetimes and the networks a document is never fetched from |
| `registration.enabled` | `true` | Whether dynamic client registration is offered |
| `registration.unusedClientLifetime` | `P1D` | How long a registered client without a grant is kept |

The cache `Flownative_OAuth2_Server_RefusedClientMetadataDocuments`
remembers refused metadata documents. If the application runs on more
than one instance, put it on a backend all instances share, such as
Redis.

## Plugging in the application

The package reaches the application through four interfaces. Each has a
default implementation; the application replaces it in its
`Objects.yaml`:

```yaml
Flownative\OAuth2\Server\IssuerResolverInterface:
  className: 'Acme\App\OAuth\HostIssuerResolver'

Flownative\OAuth2\Server\ConsentPageInterface:
  className: 'Acme\App\OAuth\ConsentPage'

Flownative\OAuth2\Server\ClientMetadataFetchThrottleInterface:
  className: 'Acme\App\OAuth\RedisFetchThrottle'

Flownative\OAuth2\Server\ErrorRedirectPolicyInterface:
  className: 'Acme\App\OAuth\ErrorRedirectPolicy'
```

### Issuer resolver

`IssuerResolverInterface::issuerFor()` tells which issuer a request
reaches. The default, `RequestHostIssuerResolver`, takes the scheme and
host of the request and accepts https requests only. An application which
serves several hosts replaces it and throws `UnknownIssuerException` for a
host it does not serve. Every grant and token belongs to one issuer, so a
token issued at one host is refused at another.

### Consent page

The authorization endpoint validates a request, stores it as a
`PendingAuthorizationRequest` and sends the browser to
`ConsentPageInterface::uriFor()`. The default, `ConfiguredConsentPage`,
sends it to `consentPagePath` with the request identifier as `?request=`.

The application's consent page then:

1. looks the request up with `AuthorizationRequests::find()`, passing the
   issuer of the current host,
2. shows the client's name and, prominently, the host the code goes to
   (`PendingAuthorizationRequest::redirectHost()`),
3. answers with `AuthorizationRequests::approve()` or `deny()` and
   redirects the browser to the address it gets back.

`approve()` creates the grant and an authorization code and returns an
`AuthorizationResponse` with the grant identifier and the redirect URI
carrying `code`, `state` and `iss`. If the application keeps its own data
about the grant, it writes it in a transaction it opens around the call.

`ConsentPageInterface::refusal()` renders a request which is refused
before its redirect URI is proved, or which may not be sent back to the
client (see the error redirect policy).

### Metadata fetch throttle

Anybody can make the server fetch a client metadata document by naming
its URL. `ClientMetadataFetchThrottleInterface::allowsFetch()` is asked
with the source address before every fetch, so that the application can
bound how many fetches one address causes. The default,
`UnthrottledClientMetadataFetches`, allows every fetch; a public server
should replace it, for example with a counter in Redis.

### Error redirect policy

Anybody can register a client with any redirect URI, so sending errors
back to an unknown client would be an open redirect.
`ErrorRedirectPolicyInterface::mayRedirectErrors()` decides whether a
refused request goes back to the client. The default,
`RedirectErrorsOfApprovedClients`, allows it only for a client which a
person approved at this issuer before; every other refusal is shown
through `ConsentPageInterface::refusal()`.

## Endpoints

All paths are below the issuer and configurable:

| Endpoint | Path | |
|---|---|---|
| Authorization | `GET /oauth/authorize` | Validates the request and sends the browser to the consent page |
| Token | `POST /oauth/token` | Exchanges a code or a refresh token |
| Registration | `POST /oauth/register` | Dynamic client registration, if enabled |
| Revocation | `POST /oauth/revoke` | Revokes the grant behind an access or refresh token |
| Authorization server metadata | `GET /.well-known/oauth-authorization-server` | RFC 8414 |
| Protected resource metadata | `GET /.well-known/oauth-protected-resource/mcp` | RFC 9728, at the plain path and below it at the configured `resourcePath` |

The endpoints need neither a session nor a CSRF token. Every request that
doesn't match one of them passes on to Flow's routing.

## Clients

### Client metadata documents

A client can use an https URL as its `client_id`. On its first
authorization request the server fetches the JSON document behind that
URL and takes the client's name and redirect URIs from it. The fetch:

- accepts https and a host name only,
- refuses hosts which resolve into one of the `deniedNetworks` (private,
  loopback, link-local and other reserved ranges), checking the address
  it actually connected to before sending the request,
- follows no redirect and reads at most `maximumBytes`,
- is cached within the configured lifetimes; a refused document is not
  fetched again for `refusalLifetime` seconds, and a cached document keeps
  serving for `staleIfErrorLifetime` seconds while fetching it again fails.

### Dynamic registration

Clients without a metadata document can register at the registration
endpoint. Only public clients are registered
(`token_endpoint_auth_method` must be `none`). A registered client which
gets no grant within `registration.unusedClientLifetime` is removed by
the garbage collection.

Redirect URIs match on their parsed parts. A loopback redirect URI
matches on any port, because a native client listens on a port of its
own choosing (RFC 8252). URIs with user info, a backslash or characters
outside RFC 3986 are refused.

## Validating tokens at the resource

The protected resource, for example an API controller or middleware of
the application, checks the bearer token with `AccessTokenValidator`:

```php
$issuer = $this->issuerResolver->issuerFor($request);
$token = $this->accessTokenValidator->validateRequest($request, $issuer);
if ($token === null) {
    return $response
        ->withStatus(401)
        ->withHeader('WWW-Authenticate', $this->endpoints->challengeFor($issuer));
}
// $token->subject, $token->clientIdentifier, $token->grantIdentifier, $token->scopes
```

A token counts only for the resource of the issuer the request reached.
`refusalOf()` tells why a token was refused; use it for the log only and
never tell the client.

## Security notes

The package leaves some checks to the application on purpose:

- **`Grants::revoke()` checks no owner.** It revokes whatever grant it is
  given; the application checks that the person may revoke it.
- **`AuthorizationRequests::approve()` trusts its subject and issuer.**
  Pass the signed-in subject and the issuer of the host the person
  approved on, never values from the request.
- **Grants are keyed by issuer, not by tenant.** A multi-tenant
  application checks its own link from the grant to the tenant of the
  host when accepting a token, besides what `AccessTokenValidator` checks.
- **`grantRevoked` slots run inside the revoking transaction.** A slot may
  write in that transaction and must not throw, or the revocation rolls
  back.
- **The consent URL carries the request identifier.** The consent page
  sends `Referrer-Policy: no-referrer` (or `same-origin`), so that the
  identifier doesn't leak to other sites.
- **A tenant that goes takes its rows with it.** The package keeps no
  tenant key, so the application deletes the grants and pending
  authorization requests of the tenant's issuers; codes and tokens
  cascade. Clients are shared by all issuers: the application removes the
  clients that kept no grant, or leaves that to the garbage collection.

## Running on Beach

The nginx of Flownative's Beach images answers `/.well-known/` paths
itself. Version 5 of the nginx image passes chosen ones on to PHP; set

```
NGINX_WELL_KNOWN_PHP_PATHS="oauth-protected-resource oauth-authorization-server"
```

so that both metadata documents reach the application. Other setups need
an equivalent rule which passes these two paths to Flow.
