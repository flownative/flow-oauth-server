<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use GuzzleHttp\Psr7\Response;
use Neos\Flow\Annotations as Flow;
use Psr\Http\Message\ResponseInterface;

/**
 * The consent page at the configured path of the issuer, given the request as
 * ?request=…, and refusals as plain text.
 */
#[Flow\Scope('singleton')]
class ConfiguredConsentPage implements ConsentPageInterface
{
    #[Flow\InjectConfiguration(path: 'consentPagePath')]
    protected string $consentPagePath;

    public function uriFor(PendingAuthorizationRequest $request): string
    {
        return $request->issuer->uriOf($this->consentPagePath) . '?' . http_build_query(['request' => $request->identifier]);
    }

    public function refusal(string $error, string $description): ResponseInterface
    {
        return new Response(400, ['Content-Type' => 'text/plain; charset=UTF-8', 'Cache-Control' => 'no-store'], $error . ': ' . $description);
    }
}
