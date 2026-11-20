<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Client;

use Flownative\OAuth2\Server\League\Client;
use JsonException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpClient\CurlHttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Fetches the JSON document a client names as its client_id. The address is
 * anybody's to name, so the fetch takes https only and a host name only,
 * lets curl resolve it within the time limit and checks the address it
 * connected to before the request is sent: a denied host sees a TCP
 * connection and a TLS handshake, never an HTTP request. It follows no
 * redirect and reads a few kilobytes at most. Flow leaves the optional
 * HTTP client to its default, which only a test replaces.
 */
#[Flow\Scope('singleton')]
class ClientMetadataDocuments
{
    private const int MAXIMUM_REDIRECT_URIS = 10;
    private const int MAXIMUM_NAME_LENGTH = 200;

    private readonly HttpClientInterface $httpClient;

    /**
     * @var array{maximumBytes: int, timeout: float, minimumCacheLifetime: int, maximumCacheLifetime: int, deniedNetworks: list<string>}
     */
    #[Flow\InjectConfiguration(path: 'clientMetadataDocuments')]
    protected array $settings;

    #[Flow\Inject]
    protected ?LoggerInterface $logger = null;

    public function __construct(?HttpClientInterface $httpClient = null)
    {
        $this->httpClient = $httpClient ?? new CurlHttpClient();
    }

    public static function isDocumentAddress(string $clientIdentifier): bool
    {
        $parts = parse_url($clientIdentifier);
        return $parts !== false
            && ($parts['scheme'] ?? '') === 'https'
            && ($parts['host'] ?? '') !== ''
            && !in_array($parts['path'] ?? '', ['', '/'], true)
            && !isset($parts['query'])
            && !isset($parts['fragment'])
            && !isset($parts['user'])
            && !isset($parts['port'])
            && RedirectUris::hostOf($clientIdentifier) !== '';
    }

    public function fetch(string $clientIdentifier): ?FetchedClientMetadataDocument
    {
        if (!self::isDocumentAddress($clientIdentifier)) {
            return null;
        }
        if (filter_var(trim(RedirectUris::hostOf($clientIdentifier), '[]'), FILTER_VALIDATE_IP) !== false) {
            return $this->refused($clientIdentifier, 'its host is an address, not a name');
        }
        $deniedNetworks = DeniedNetworks::fromCidrRanges($this->settings['deniedNetworks']);
        $isAllowed = static fn (mixed $address): bool => is_string($address) && $address !== '' && !$deniedNetworks->contains($address);
        $maximumBytes = $this->settings['maximumBytes'];
        try {
            $response = $this->httpClient->request('GET', $clientIdentifier, [
                'headers' => ['Accept' => 'application/json'],
                // A proxy would connect in our place, past the check of the address.
                'no_proxy' => '*',
                'max_redirects' => 0,
                'timeout' => $this->settings['timeout'],
                'max_duration' => $this->settings['timeout'],
                'on_progress' => static function (int $downloaded, int $size, array $info) use ($maximumBytes, $isAllowed): void {
                    if (($info['primary_ip'] ?? '') !== '' && !$isAllowed($info['primary_ip'])) {
                        throw new DeniedAddressException('The host of the client metadata document is in a denied network', 1795160001);
                    }
                    if ($downloaded > $maximumBytes) {
                        throw new DocumentTooLargeException('The client metadata document is too large', 1795083649);
                    }
                },
                'extra' => ['curl' => [
                    // Runs after the TCP and TLS handshakes and before the request is sent, so a denied host never gets the request.
                    CURLOPT_PREREQFUNCTION => static fn (mixed $handle, string $primaryAddress): int => $isAllowed($primaryAddress) ? CURL_PREREQFUNC_OK : CURL_PREREQFUNC_ABORT,
                ]],
            ]);
            if ($response->getStatusCode() !== 200 || !str_starts_with(strtolower($response->getHeaders()['content-type'][0] ?? ''), 'application/json')) {
                return $this->refused($clientIdentifier, 'it did not answer 200 with JSON');
            }
            if (!$isAllowed($response->getInfo('primary_ip'))) {
                return $this->refused($clientIdentifier, 'its host is no name on the public network');
            }
            $content = $response->getContent();
            $cacheControl = implode(',', $response->getHeaders()['cache-control'] ?? []);
        } catch (ExceptionInterface|DocumentTooLargeException|DeniedAddressException $exception) {
            return $this->refused($clientIdentifier, $exception->getMessage());
        }
        if (strlen($content) > $maximumBytes) {
            return $this->refused($clientIdentifier, 'it is too large');
        }
        try {
            $document = json_decode($content, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $this->refused($clientIdentifier, 'it is no JSON');
        }
        if ($clientIdentifier === '' || !is_array($document) || ($document['client_id'] ?? null) !== $clientIdentifier) {
            return $this->refused($clientIdentifier, 'it names another client_id');
        }
        $redirectUris = $document['redirect_uris'] ?? null;
        if (!is_array($redirectUris) || $redirectUris === [] || count($redirectUris) > self::MAXIMUM_REDIRECT_URIS || !array_is_list($redirectUris)) {
            return $this->refused($clientIdentifier, 'it lists no redirect URIs');
        }
        $acceptedRedirectUris = [];
        foreach ($redirectUris as $redirectUri) {
            if (!is_string($redirectUri) || !RedirectUris::isAcceptable($redirectUri)) {
                return $this->refused($clientIdentifier, 'it lists a redirect URI that is not accepted');
            }
            $acceptedRedirectUris[] = $redirectUri;
        }
        if (($document['token_endpoint_auth_method'] ?? 'none') !== 'none') {
            return $this->refused($clientIdentifier, 'it asks for client authentication');
        }
        $name = $document['client_name'] ?? null;
        $name = is_string($name) && trim($name) !== '' ? mb_substr(trim($name), 0, self::MAXIMUM_NAME_LENGTH) : RedirectUris::hostOf($clientIdentifier);

        return new FetchedClientMetadataDocument(
            new Client($clientIdentifier, $name, $acceptedRedirectUris),
            $this->cacheLifetime($cacheControl),
        );
    }

    private function cacheLifetime(string $cacheControl): int
    {
        $maximum = $this->settings['maximumCacheLifetime'];
        $minimum = min($this->settings['minimumCacheLifetime'], $maximum);
        if (preg_match('/(?:^|,)\s*(?:no-store|no-cache)\s*(?:,|$)/i', $cacheControl) === 1) {
            return $minimum;
        }
        if (preg_match('/max-age\s*=\s*(\d+)/i', $cacheControl, $matches) === 1) {
            return max($minimum, min((int)$matches[1], $maximum));
        }
        return $maximum;
    }

    private function refused(string $clientIdentifier, string $reason): null
    {
        $this->logger?->notice(sprintf('The client metadata document at %s was refused: %s', $clientIdentifier, $reason), LogEnvironment::fromMethodName(__METHOD__));
        return null;
    }
}
