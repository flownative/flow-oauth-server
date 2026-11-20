<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Unit;

use Flownative\OAuth2\Server\AccessTokenValidator;
use Flownative\OAuth2\Server\Grants;
use Flownative\OAuth2\Server\League\AuthorizationCodes;
use Flownative\OAuth2\Server\League\DbalAccessTokenRepository;
use Flownative\OAuth2\Server\League\DbalClientRepository;
use Flownative\OAuth2\Server\League\DbalRefreshTokenRepository;
use Flownative\OAuth2\Server\TokenSecret;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use SensitiveParameter;

/**
 * A secret in plain text must not show up in the backtrace of an exception.
 */
final class SensitiveParametersTest extends TestCase
{
    /**
     * @return iterable<string, array{class-string, string, string}>
     */
    public static function secretParameters(): iterable
    {
        yield 'validate' => [AccessTokenValidator::class, 'validate', 'accessToken'];
        yield 'refusalOf' => [AccessTokenValidator::class, 'refusalOf', 'accessToken'];
        yield 'revokeByToken' => [Grants::class, 'revokeByToken', 'token'];
        yield 'code spend' => [AuthorizationCodes::class, 'spend', 'code'];
        yield 'code spentBefore' => [AuthorizationCodes::class, 'spentBefore', 'code'];
        yield 'refresh token spend' => [DbalRefreshTokenRepository::class, 'spend', 'secret'];
        yield 'refresh token spentBefore' => [DbalRefreshTokenRepository::class, 'spentBefore', 'secret'];
        yield 'refresh token wasSpentWithin' => [DbalRefreshTokenRepository::class, 'wasSpentWithin', 'secret'];
        yield 'revokeRefreshToken' => [DbalRefreshTokenRepository::class, 'revokeRefreshToken', 'tokenId'];
        yield 'isRefreshTokenRevoked' => [DbalRefreshTokenRepository::class, 'isRefreshTokenRevoked', 'tokenId'];
        yield 'revokeAccessToken' => [DbalAccessTokenRepository::class, 'revokeAccessToken', 'tokenId'];
        yield 'isAccessTokenRevoked' => [DbalAccessTokenRepository::class, 'isAccessTokenRevoked', 'tokenId'];
        yield 'validateClient' => [DbalClientRepository::class, 'validateClient', 'clientSecret'];
        yield 'digest' => [TokenSecret::class, 'digest', 'secret'];
    }

    /**
     * @param class-string $className
     */
    #[DataProvider('secretParameters')]
    public function testSecretParameterIsMarkedSensitive(string $className, string $methodName, string $parameterName): void
    {
        foreach ((new ReflectionMethod($className, $methodName))->getParameters() as $parameter) {
            if ($parameter->getName() === $parameterName) {
                self::assertNotEmpty($parameter->getAttributes(SensitiveParameter::class));
                return;
            }
        }
        self::fail(sprintf('%s::%s() has no parameter $%s', $className, $methodName, $parameterName));
    }
}
