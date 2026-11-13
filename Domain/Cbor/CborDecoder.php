<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain\Cbor;

use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;

/**
 * A CBOR decoder for the subset CTAP2 permits.
 *
 * WHY A SUBSET IS THE SAFER IMPLEMENTATION
 * ----------------------------------------
 * CBOR has features WebAuthn never uses and which, accepted, become attack
 * surface on the only parser standing between an unauthenticated HTTP body and
 * this application's credential store:
 *
 *   - **indefinite-length** strings, arrays and maps (additional info 31). CTAP2
 *     forbids them. A decoder that supports them has to track nesting state
 *     across a break marker, and a hostile `BREAK` in the wrong place is how
 *     such parsers get confused about where one item ends;
 *   - **tags** (major type 6). None is meaningful here, and a tag wrapping a
 *     byte string is a second way to express the same value — which means two
 *     parsers can disagree about what a message said;
 *   - **duplicate map keys**. Not rejected by the format, and a real hazard:
 *     one parser keeps the first value and another keeps the last, so an
 *     attestation object can say two different things depending on who reads
 *     it. Rejected here.
 *
 * Canonical ORDERING, which CTAP2 also requires, is NOT enforced. That is a
 * considered asymmetry: a non-canonical order cannot create a disagreement
 * about meaning, and real authenticators have shipped with ordering bugs — so
 * enforcing it would reject working hardware to no security benefit.
 *
 * THE CURSOR IS PART OF THE INTERFACE, not an implementation detail. A COSE key
 * sits inside authenticator data with extension bytes possibly after it, so the
 * caller has to learn how many bytes the key consumed. A decoder that only
 * offered "decode this whole string" would force the caller to guess, and
 * guessing wrong means either rejecting a credential with extensions or reading
 * the extensions as part of the key.
 */
final class CborDecoder
{
    /**
     * Nesting limit.
     *
     * Not a performance guard. PHP has no tail calls, so a deeply nested CBOR
     * document recurses until the stack is exhausted — which is a segmentation
     * fault, not an exception, and takes the worker with it. Twelve is far more
     * than any WebAuthn structure needs; an attestation object is three deep.
     */
    private const MAX_DEPTH = 12;

    private int $position = 0;

    public function __construct(private readonly string $bytes) {}

    /**
     * Decode exactly one item from $bytes and require the whole string to be
     * consumed.
     *
     * The trailing-bytes check is the reason this helper exists. An
     * attestation object with extra bytes after its map is not a document this
     * code understands, and "parse the beginning and ignore the rest" is how a
     * parser ends up agreeing with an attacker about a prefix and with nobody
     * about the whole.
     */
    public static function decodeAll(string $bytes, string $what = 'CBOR value'): mixed
    {
        $decoder = new self($bytes);
        $value   = $decoder->next();

        if (!$decoder->atEnd()) {
            throw WebAuthnException::malformed(
                "The {$what} has " . (\strlen($bytes) - $decoder->position()) . ' unexpected trailing bytes.',
            );
        }

        return $value;
    }

    /** The next item, advancing the cursor. */
    public function next(): mixed
    {
        return $this->item(0);
    }

    public function position(): int
    {
        return $this->position;
    }

    public function atEnd(): bool
    {
        return $this->position >= \strlen($this->bytes);
    }

    private function item(int $depth): mixed
    {
        if ($depth > self::MAX_DEPTH) {
            throw WebAuthnException::malformed('The CBOR value is nested too deeply.');
        }

        $initial        = \ord($this->take(1));
        $major          = $initial >> 5;
        $additionalInfo = $initial & 0x1F;

        if ($additionalInfo === 31) {
            throw WebAuthnException::malformed(
                'The CBOR value uses an indefinite length, which CTAP2 forbids.',
            );
        }

        return match ($major) {
            0 => $this->argument($additionalInfo),
            1 => -1 - $this->argument($additionalInfo),
            2 => $this->take($this->length($additionalInfo)),
            3 => $this->text($this->length($additionalInfo)),
            4 => $this->array($this->length($additionalInfo), $depth),
            5 => $this->map($this->length($additionalInfo), $depth),
            6 => throw WebAuthnException::malformed('The CBOR value uses a tag, which is not expected here.'),
            default => $this->simple($additionalInfo),
        };
    }

    /** The integer argument that follows the initial byte. */
    private function argument(int $additionalInfo): int
    {
        if ($additionalInfo < 24) {
            return $additionalInfo;
        }

        if ($additionalInfo === 24) {
            return \ord($this->take(1));
        }

        /** @var array{1: int} $unpacked */
        $unpacked = match ($additionalInfo) {
            25 => unpack('n', $this->take(2)),
            26 => unpack('N', $this->take(4)),
            27 => unpack('J', $this->take(8)),
            default => throw WebAuthnException::malformed(
                "The CBOR value uses reserved additional information {$additionalInfo}.",
            ),
        };

        $value = $unpacked[1];

        // An eight-byte length read as a signed 64-bit integer can come back
        // negative, and a negative length would make every bounds check below
        // pass. No WebAuthn field is anywhere near this large.
        if ($value < 0) {
            throw WebAuthnException::malformed('The CBOR value declares a length beyond the integer range.');
        }

        return $value;
    }

    /**
     * An argument used as a length, bounded by what is actually left.
     *
     * Checked HERE rather than in take(), so the error says the declared length
     * was impossible rather than that the string ran out — the two have
     * different causes and a truncated upload is the common one.
     */
    private function length(int $additionalInfo): int
    {
        $length    = $this->argument($additionalInfo);
        $remaining = \strlen($this->bytes) - $this->position;

        if ($length > $remaining) {
            throw WebAuthnException::malformed(
                "The CBOR value declares {$length} bytes but only {$remaining} remain.",
            );
        }

        return $length;
    }

    private function text(int $length): string
    {
        $value = $this->take($length);

        // A text string is UTF-8 by definition. Invalid UTF-8 reaching a JSON
        // encoder later fails there instead, a long way from the cause.
        if ($length > 0 && !mb_check_encoding($value, 'UTF-8')) {
            throw WebAuthnException::malformed('A CBOR text string is not valid UTF-8.');
        }

        return $value;
    }

    /** @return list<mixed> */
    private function array(int $count, int $depth): array
    {
        $items = [];

        for ($i = 0; $i < $count; ++$i) {
            $items[] = $this->item($depth + 1);
        }

        return $items;
    }

    /** @return array<int|string, mixed> */
    private function map(int $count, int $depth): array
    {
        $map = [];

        for ($i = 0; $i < $count; ++$i) {
            $key = $this->item($depth + 1);

            if (!\is_int($key) && !\is_string($key)) {
                throw WebAuthnException::malformed('A CBOR map key is neither an integer nor a string.');
            }

            if (\array_key_exists($key, $map)) {
                throw WebAuthnException::malformed("The CBOR map repeats the key [{$key}].");
            }

            $map[$key] = $this->item($depth + 1);
        }

        return $map;
    }

    private function simple(int $additionalInfo): bool|float|null
    {
        return match ($additionalInfo) {
            20 => false,
            21 => true,
            22 => null,
            // `undefined` is distinct from `null` in CBOR and has no PHP
            // equivalent. Mapping it to null would make a field that was
            // explicitly undefined indistinguishable from one that was null.
            23 => throw WebAuthnException::malformed('The CBOR value contains `undefined`.'),
            25 => $this->halfPrecision(),
            26 => $this->floatFrom('G', 4),
            27 => $this->floatFrom('E', 8),
            default => throw WebAuthnException::malformed(
                "The CBOR value uses unsupported simple value {$additionalInfo}.",
            ),
        };
    }

    /**
     * IEEE 754 half precision, which PHP's `unpack` cannot read.
     *
     * Present because CBOR encoders emit it for small values and a decoder that
     * rejected it would be wrong about valid documents — not because anything
     * in WebAuthn is a float. Implemented by hand: sign, a five-bit exponent
     * with a bias of 15, and a ten-bit mantissa.
     */
    private function halfPrecision(): float
    {
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('n', $this->take(2));
        $raw      = $unpacked[1];

        $sign     = ($raw >> 15) & 0x1;
        $exponent = ($raw >> 10) & 0x1F;
        $mantissa = $raw & 0x3FF;

        $value = match (true) {
            $exponent === 0    => $mantissa * 2 ** -24,
            $exponent === 0x1F => $mantissa === 0 ? INF : NAN,
            default            => ($mantissa + 1024) * 2 ** ($exponent - 25),
        };

        return $sign === 1 ? -$value : $value;
    }

    private function floatFrom(string $format, int $width): float
    {
        /** @var array{1: float} $unpacked */
        $unpacked = unpack($format, $this->take($width));

        return $unpacked[1];
    }

    private function take(int $length): string
    {
        if ($length < 0 || $this->position + $length > \strlen($this->bytes)) {
            throw WebAuthnException::malformed('The CBOR value is truncated.');
        }

        $slice = substr($this->bytes, $this->position, $length);
        $this->position += $length;

        return $slice;
    }
}
