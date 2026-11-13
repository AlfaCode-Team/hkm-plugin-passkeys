<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Passkeys;

/**
 * A minimal CBOR ENCODER, for the test side only.
 *
 * Explicit about text versus byte strings, because CBOR distinguishes them and
 * a WebAuthn structure uses both: the attestation object's keys are text and
 * its `authData` is bytes. An encoder that guessed would produce documents no
 * real authenticator sends.
 *
 * @internal
 */
final class Cbor
{
    public static function int(int $value): string
    {
        return $value >= 0
            ? self::head(0, $value)
            : self::head(1, -1 - $value);
    }

    public static function bytes(string $value): string
    {
        return self::head(2, \strlen($value)) . $value;
    }

    public static function text(string $value): string
    {
        return self::head(3, \strlen($value)) . $value;
    }

    /** @param list<string> $items already-encoded */
    public static function array(array $items): string
    {
        return self::head(4, \count($items)) . implode('', $items);
    }

    /** @param list<array{0: string, 1: string}> $pairs already-encoded key/value */
    public static function map(array $pairs): string
    {
        $encoded = '';

        foreach ($pairs as [$key, $value]) {
            $encoded .= $key . $value;
        }

        return self::head(5, \count($pairs)) . $encoded;
    }

    private static function head(int $major, int $value): string
    {
        $prefix = $major << 5;

        return match (true) {
            $value < 24      => \chr($prefix | $value),
            $value < 0x100   => \chr($prefix | 24) . \chr($value),
            $value < 0x10000 => \chr($prefix | 25) . pack('n', $value),
            default          => \chr($prefix | 26) . pack('N', $value),
        };
    }
}
