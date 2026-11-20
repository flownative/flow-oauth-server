<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server\Tests\Functional\Fixtures;

use Doctrine\DBAL\DriverManager;
use Flownative\OAuth2\Server\DatabasePlatform;
use Flownative\OAuth2\Server\League\AuthorizationCodes;
use Flownative\OAuth2\Server\League\DbalRefreshTokenRepository;

/**
 * The first of two racing exchanges, run in a process of its own: it spends
 * a code or refresh token in a transaction, says "held" and commits only
 * after a while, so that the test's second exchange waits for its locks.
 *
 * The order comes as a JSON object on standard input: connection
 * parameters, credential ("code" or "refresh token"), secret, holdSeconds
 * and spentSecondsAgo, which moves the spend into the past.
 */
final class SpendingProcess
{
    /**
     * The command which runs the process with the application's autoloader.
     *
     * @return list<string>
     */
    public static function command(): array
    {
        return [PHP_BINARY, '-r', 'require $argv[1]; require $argv[2]; ' . self::class . '::main();', FLOW_PATH_PACKAGES . 'Libraries/autoload.php', __FILE__];
    }

    public static function main(): void
    {
        $order = json_decode((string)stream_get_contents(STDIN), true, 8, JSON_THROW_ON_ERROR);
        $connection = DriverManager::getConnection($order['connection']);
        $connection->beginTransaction();
        $spent = $order['credential'] === 'code'
            ? (new AuthorizationCodes($connection))->spend($order['secret'])
            : (new DbalRefreshTokenRepository($connection))->spend($order['secret']);
        if ($spent === null) {
            fwrite(STDOUT, "not spent\n");
            exit(1);
        }
        if ($order['spentSecondsAgo'] > 0) {
            $table = $order['credential'] === 'code' ? 'flownative_oauth2_server_authorization_code' : 'flownative_oauth2_server_refresh_token';
            $earlier = match (DatabasePlatform::of($connection)) {
                DatabasePlatform::POSTGRESQL => sprintf("spent_at - interval '%d seconds'", $order['spentSecondsAgo']),
                DatabasePlatform::MYSQL => sprintf('spent_at - INTERVAL %d SECOND', $order['spentSecondsAgo']),
            };
            $connection->executeStatement("UPDATE {$table} SET spent_at = {$earlier} WHERE spent_at IS NOT NULL");
        }
        fwrite(STDOUT, "held\n");
        sleep($order['holdSeconds']);
        $connection->commit();
    }
}
