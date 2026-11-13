<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;

/**
 * base64url, which is what every binary field in WebAuthn arrives as.
 *
 * DECODING IS STRICT, AND THAT IS THE WHOLE POINT OF THIS CLASS
 * -------------------------------------------------------------
 * `base64_decode($x, true)` already rejects malformed input, and the trap is
 * the character set rather than the padding. base64url uses `-` and `_` where
 * standard base64 uses `+` and `/`; standard `base64_decode` in non-strict mode
 * SKIPS characters it does not recognise. So a value containing `-` decodes to
 * something shorter than it should, silently, and the comparison that follows
 * is between two things that are both wrong.
 *
 * That matters here more than in most places, because the values being decoded
 * are a challenge and a credential id — both of which are compared for equality
 * to decide whether someone is who they say they are. A decoder that quietly
 * drops bytes is a decoder that can be steered into collisions.
 *
 * So: translate first, then decode in STRICT mode, then reject anything that
 * did not round-trip. Nothing about a WebAuthn field is allowed to be
 * approximately right.
 */
final class Base64Url
{
    /** Without padding, which is what the WebAuthn JSON serialisation uses. */
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * @throws WebAuthnException when $value is not valid base64url
     */
    public static function decode(string $value, string $what = 'value'): string
    {
        if ($value === '') {
            throw WebAuthnException::malformed("The {$what} is empty.");
        }

        // Only the base64url alphabet, and the padding the serialisation omits.
        if (preg_match('/^[A-Za-z0-9\-_]+=*$/', $value) !== 1) {
            throw WebAuthnException::malformed("The {$what} is not base64url.");
        }

        $standard = strtr(rtrim($value, '='), '-_', '+/');
        $padding  = \strlen($standard) % 4;

        if ($padding === 1) {
            // A base64 group is never one character long. Left to strict
            // decoding this returns false, which is correct but loses the
            // chance to say what was wrong.
            throw WebAuthnException::malformed("The {$what} has a truncated base64 group.");
        }

        if ($padding > 0) {
            $standard .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode($standard, true);

        if ($decoded === false) {
            throw WebAuthnException::malformed("The {$what} is not valid base64.");
        }

        return $decoded;
    }

    /**
     * Constant-time equality of two base64url values.
     *
     * Used for the credential id, and `hash_equals` rather than `===` because
     * the project's rules say so for anything token-shaped — a credential id is
     * a public identifier rather than a secret, so the timing channel is not
     * exploitable here, but writing `===` in a comparison of security-relevant
     * identifiers invites the next one to be copied from it.
     */
    public static function same(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }
}
