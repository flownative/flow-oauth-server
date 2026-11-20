<?php

declare(strict_types=1);

namespace Flownative\OAuth2\Server;

use RuntimeException;

/**
 * Typed reads from the rows the package's own tables return.
 */
final class Rows
{
    /**
     * @param array<string, mixed> $row
     */
    public static function string(array $row, string $column): string
    {
        $value = $row[$column] ?? null;
        if (!is_string($value)) {
            throw new RuntimeException(sprintf('The column "%s" holds no text', $column), 1795083647);
        }
        return $value;
    }

    /**
     * @param array<string, mixed> $row
     */
    public static function nullableString(array $row, string $column): ?string
    {
        $value = $row[$column] ?? null;
        return $value === null ? null : self::string($row, $column);
    }

    /**
     * @param array<string, mixed> $row
     * @return list<string>
     */
    public static function stringList(array $row, string $column): array
    {
        $values = json_decode(self::string($row, $column), true, 4, JSON_THROW_ON_ERROR);
        if (!is_array($values) || !array_is_list($values)) {
            throw new RuntimeException(sprintf('The column "%s" holds no list', $column), 1795083648);
        }
        return array_values(array_filter($values, 'is_string'));
    }
}
