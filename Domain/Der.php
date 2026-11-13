<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

/**
 * Just enough DER to build a SubjectPublicKeyInfo.
 *
 * WHY THIS EXISTS INSTEAD OF A HARD-CODED PREFIX
 * ----------------------------------------------
 * The usual way to turn a COSE P-256 key into something OpenSSL will load is to
 * concatenate a 26-byte magic string with the coordinates:
 *
 *     3059301306072a8648ce3d020106082a8648ce3d030107034200 04 ‖ x ‖ y
 *
 * That works, and it is unreviewable. Nobody reading it can tell whether the
 * length bytes are right, and the one thing that WILL be wrong eventually is a
 * length — because the trick only holds while every key is exactly 65 bytes.
 * Add RSA, whose modulus is 256 or 512 bytes and needs multi-byte length
 * encoding, and the magic-string approach has to grow a length encoder anyway.
 *
 * So the length encoder is here, written once, with the short-form and
 * long-form rules visible. {@see CoseKey} then composes the structures from the
 * ASN.1 in the RFCs, which can be read side by side with the specification.
 *
 * Only the encoder is implemented. Nothing here PARSES DER, which is
 * deliberate: parsing attacker-supplied ASN.1 is a notorious source of
 * vulnerabilities, and this plugin never needs to — the only DER it handles is
 * what it builds itself, and a certificate chain it would have to parse is
 * exactly the attestation format it refuses.
 */
final class Der
{
    public const SEQUENCE   = 0x30;
    public const INTEGER    = 0x02;
    public const BIT_STRING = 0x03;
    public const OID        = 0x06;
    public const NULL       = 0x05;

    /**
     * A tag, a length and the contents.
     *
     * @param int<0, 255> $tag a single identifier octet — every tag this
     *                         plugin uses is one of the constants above
     */
    public static function encode(int $tag, string $contents): string
    {
        return \chr($tag) . self::length(\strlen($contents)) . $contents;
    }

    public static function sequence(string ...$parts): string
    {
        return self::encode(self::SEQUENCE, implode('', $parts));
    }

    /**
     * An INTEGER holding an unsigned big-endian value.
     *
     * The leading-zero rule is the one thing to get right. DER integers are
     * SIGNED two's complement, so a value whose top bit is set needs a `0x00`
     * in front or it reads as negative — and an RSA modulus has its top bit set
     * roughly half the time. Without this, half of all RSA keys would be
     * rejected by OpenSSL and the other half would work, which is the most
     * confusing possible failure rate.
     *
     * Leading zero bytes are also stripped first, since DER requires the
     * shortest form and some encoders pad.
     */
    public static function unsignedInteger(string $bytes): string
    {
        $trimmed = ltrim($bytes, "\x00");

        if ($trimmed === '') {
            return self::encode(self::INTEGER, "\x00");
        }

        if ((\ord($trimmed[0]) & 0x80) !== 0) {
            $trimmed = "\x00" . $trimmed;
        }

        return self::encode(self::INTEGER, $trimmed);
    }

    /**
     * A BIT STRING with no unused trailing bits.
     *
     * The leading `0x00` is the unused-bit count, which is always zero for the
     * byte-aligned keys here. It is part of the contents, not the header — a
     * detail that is easy to misplace and produces a key OpenSSL loads with the
     * first byte shifted.
     */
    public static function bitString(string $bytes): string
    {
        return self::encode(self::BIT_STRING, "\x00" . $bytes);
    }

    /** An OBJECT IDENTIFIER from its dotted form, e.g. `1.2.840.10045.2.1`. */
    public static function oid(string $dotted): string
    {
        $arcs = array_map('intval', explode('.', $dotted));

        // The first two arcs share one byte: 40 * first + second. A quirk of
        // the encoding rather than of this code, and the reason an OID cannot
        // simply be a list of base-128 numbers.
        $encoded = self::base128($arcs[0] * 40 + $arcs[1]);

        foreach (\array_slice($arcs, 2) as $arc) {
            $encoded .= self::base128($arc);
        }

        return self::encode(self::OID, $encoded);
    }

    public static function null(): string
    {
        return self::encode(self::NULL, '');
    }

    /** PEM, which is what `openssl_pkey_get_public()` wants. */
    public static function toPem(string $der, string $label = 'PUBLIC KEY'): string
    {
        return "-----BEGIN {$label}-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END {$label}-----\n";
    }

    /**
     * DER length: short form under 128, long form above.
     *
     * The long form is a byte saying how many length bytes follow, with the
     * high bit set. This is the rule a hard-coded prefix hides, and the one that
     * breaks the moment a key is larger than 127 bytes — which every RSA key
     * is.
     */
    /** @param int<0, max> $length */
    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return \chr($length);
        }

        $bytes = '';

        for ($remaining = $length; $remaining > 0; $remaining >>= 8) {
            $bytes = \chr($remaining & 0xFF) . $bytes;
        }

        $count = \strlen($bytes);

        // Unreachable for anything this plugin encodes — the largest structure
        // is an RSA SubjectPublicKeyInfo at a few hundred bytes, needing two
        // length octets. It is here so the octet below is PROVABLY a byte
        // rather than relying on the reader to count loop iterations, and
        // because the alternative on an impossible input is a silently
        // truncated length that produces a structure nothing can parse.
        // Only the upper bound: the loop above runs at least once for any
        // $length that reached here, so $count is at least 1 by construction.
        if ($count > 0x7E) {
            throw new \LengthException("A DER value of {$length} bytes cannot have its length encoded.");
        }

        return \chr(0x80 | $count) . $bytes;
    }

    /** Base-128, high bit set on every byte but the last. */
    private static function base128(int $value): string
    {
        $bytes = \chr($value & 0x7F);

        for ($remaining = $value >> 7; $remaining > 0; $remaining >>= 7) {
            $bytes = \chr(0x80 | ($remaining & 0x7F)) . $bytes;
        }

        return $bytes;
    }
}
