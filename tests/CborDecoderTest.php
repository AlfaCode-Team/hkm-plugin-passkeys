<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\Passkeys\Domain\Cbor\CborDecoder;
use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;

/**
 * The CBOR decoder, against byte sequences from RFC 8949 Appendix A.
 *
 * WHY THE VECTORS ARE WRITTEN AS LITERAL HEX
 * ------------------------------------------
 * Because {@see FakeAuthenticator} contains this test suite's own CBOR
 * *encoder*, and a suite that only round-tripped through it would pass with a
 * matching bug on both sides — the encoder writing a length one byte short and
 * the decoder reading it one byte short would agree perfectly and agree with
 * nothing else.
 *
 * The sequences below were not produced by any code in this repository. They
 * are the specification's own examples, so they are the one place the decoder
 * is checked against an outside authority.
 */
#[CoversClass(CborDecoder::class)]
final class CborDecoderTest extends TestCase
{
    /** @return iterable<string, array{0: string, 1: mixed}> */
    public static function vectors(): iterable
    {
        // Unsigned integers, across every argument width.
        yield '00 → 0'                       => ['00', 0];
        yield '0a → 10'                      => ['0a', 10];
        yield '17 → 23 (the last direct)'    => ['17', 23];
        yield '1818 → 24 (one extra byte)'   => ['1818', 24];
        yield '1819 → 25'                    => ['1819', 25];
        yield '1864 → 100'                   => ['1864', 100];
        yield '1903e8 → 1000 (two bytes)'    => ['1903e8', 1000];
        yield '1a000f4240 → 1e6 (four)'      => ['1a000f4240', 1000000];
        yield '1b000000e8d4a51000 → 1e12'    => ['1b000000e8d4a51000', 1000000000000];

        // Negative integers: the encoded argument is -1 - n.
        yield '20 → -1'                      => ['20', -1];
        yield '29 → -10'                     => ['29', -10];
        yield '3863 → -100'                  => ['3863', -100];
        yield '3903e7 → -1000'               => ['3903e7', -1000];

        yield '40 → empty byte string'       => ['40', ''];
        yield '4401020304 → four bytes'      => ['4401020304', "\x01\x02\x03\x04"];

        yield '60 → empty text'              => ['60', ''];
        yield '6161 → "a"'                   => ['6161', 'a'];
        yield '6449455446 → "IETF"'          => ['6449455446', 'IETF'];
        yield '62225c → "\\"\\\\"'           => ['62225c', '"\\'];
        yield '62c3bc → "ü" (two-byte utf8)' => ['62c3bc', 'ü'];

        yield '80 → []'                      => ['80', []];
        yield '83010203 → [1,2,3]'           => ['83010203', [1, 2, 3]];
        yield '8301820203820405 → nested'    => ['8301820203820405', [1, [2, 3], [4, 5]]];

        yield 'a0 → {}'                      => ['a0', []];
        yield 'a201020304 → {1:2,3:4}'       => ['a201020304', [1 => 2, 3 => 4]];
        yield 'a26161016162820203'           => ['a26161016162820203', ['a' => 1, 'b' => [2, 3]]];
        yield '826161a161626163'             => ['826161a161626163', ['a', ['b' => 'c']]];

        yield 'f4 → false'                   => ['f4', false];
        yield 'f5 → true'                    => ['f5', true];
        yield 'f6 → null'                    => ['f6', null];
    }

    #[DataProvider('vectors')]
    public function test_the_rfc_vectors_decode(string $hex, mixed $expected): void
    {
        self::assertSame($expected, CborDecoder::decodeAll((string) hex2bin($hex)));
    }

    /** @return iterable<string, array{0: string, 1: float}> */
    public static function floatVectors(): iterable
    {
        // Half precision, which PHP's unpack cannot read and which this
        // decoder assembles by hand from sign, exponent and mantissa.
        yield 'f93c00 → 1.0 (half)'       => ['f93c00', 1.0];
        yield 'f93e00 → 1.5 (half)'       => ['f93e00', 1.5];
        yield 'f97bff → 65504.0 (half)'   => ['f97bff', 65504.0];
        yield 'f9c400 → -4.0 (half)'      => ['f9c400', -4.0];
        yield 'f90001 → subnormal (half)' => ['f90001', 5.960464477539063e-8];

        yield 'fa47c35000 → 100000.0'     => ['fa47c35000', 100000.0];
        yield 'fb3ff199999999999a → 1.1'  => ['fb3ff199999999999a', 1.1];
        yield 'fbc010666666666666 → -4.1' => ['fbc010666666666666', -4.1];
    }

    #[DataProvider('floatVectors')]
    public function test_floats_decode(string $hex, float $expected): void
    {
        $decoded = CborDecoder::decodeAll((string) hex2bin($hex));

        self::assertIsFloat($decoded);
        self::assertEqualsWithDelta($expected, $decoded, abs($expected) * 1e-9 + 1e-12);
    }

    public function test_half_precision_infinity_and_nan(): void
    {
        self::assertSame(INF, CborDecoder::decodeAll((string) hex2bin('f97c00')));
        self::assertSame(-INF, CborDecoder::decodeAll((string) hex2bin('f9fc00')));
        self::assertNan((float) CborDecoder::decodeAll((string) hex2bin('f97e00')));
    }

    // ── What is refused, and why ──────────────────────────────────────────────

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function refusals(): iterable
    {
        // CTAP2 forbids indefinite lengths. A decoder that supports them has to
        // track nesting across a break marker, which is where such parsers get
        // confused about where an item ends.
        yield 'indefinite byte string' => ['5f42010243030405ff', 'indefinite length'];
        yield 'indefinite text string' => ['7f657374726561646d696e67ff', 'indefinite length'];
        yield 'indefinite array'       => ['9f018202039f0203ffff', 'indefinite length'];
        yield 'indefinite map'         => ['bf61610161629f0203ffff', 'indefinite length'];

        // A tag wrapping a value is a second way to express it, which means two
        // parsers can disagree about what a message said.
        yield 'a tag'                  => ['c11a514b67b0', 'uses a tag'];

        // `undefined` is distinct from null in CBOR and has no PHP equivalent;
        // mapping it to null would conflate two different statements.
        yield 'undefined'              => ['f7', 'undefined'];

        // Reserved additional information 28–30.
        yield 'reserved argument 28'   => ['1c', 'reserved additional information'];

        yield 'truncated integer'      => ['19', 'truncated'];
        yield 'truncated byte string'  => ['4401', 'only'];
        yield 'empty input'            => ['', 'truncated'];
    }

    #[DataProvider('refusals')]
    public function test_what_ctap2_forbids_is_refused(string $hex, string $reasonFragment): void
    {
        try {
            CborDecoder::decodeAll((string) hex2bin($hex));
            self::fail("[{$hex}] was accepted; expected a refusal");
        } catch (WebAuthnException $e) {
            self::assertStringContainsString($reasonFragment, $e->reason);
        }
    }

    /**
     * Not forbidden by the format, and a real hazard: one parser keeps the
     * first value and another keeps the last, so one document says two
     * different things depending on who reads it.
     */
    public function test_a_duplicate_map_key_is_refused(): void
    {
        // {1: 2, 1: 3}
        try {
            CborDecoder::decodeAll((string) hex2bin('a201020103'));
            self::fail('a duplicate key was accepted');
        } catch (WebAuthnException $e) {
            self::assertStringContainsString('repeats the key', $e->reason);
        }
    }

    /**
     * "Parse the beginning and ignore the rest" is how a parser ends up
     * agreeing with an attacker about a prefix and with nobody about the whole.
     */
    public function test_trailing_bytes_are_refused(): void
    {
        try {
            CborDecoder::decodeAll((string) hex2bin('00ffffff'));
            self::fail('trailing bytes were accepted');
        } catch (WebAuthnException $e) {
            self::assertStringContainsString('trailing bytes', $e->reason);
        }
    }

    /**
     * PHP has no tail calls, so unbounded nesting exhausts the C stack — a
     * segmentation fault rather than an exception, which takes the worker with
     * it instead of returning a 422.
     */
    public function test_deep_nesting_is_refused_rather_than_crashing(): void
    {
        // 40 nested single-element arrays.
        $bytes = str_repeat("\x81", 40) . "\x00";

        try {
            CborDecoder::decodeAll($bytes);
            self::fail('deeply nested input was accepted');
        } catch (WebAuthnException $e) {
            self::assertStringContainsString('nested too deeply', $e->reason);
        }
    }

    /**
     * A declared length larger than the data must be caught by the DECLARATION
     * check, not by running off the end — a hostile 4 GB length should not
     * cause an allocation attempt first.
     */
    public function test_an_absurd_declared_length_is_refused_immediately(): void
    {
        // A byte string declaring 0xFFFFFFFF bytes, with none following.
        try {
            CborDecoder::decodeAll("\x5a\xff\xff\xff\xff");
            self::fail('an absurd length was accepted');
        } catch (WebAuthnException $e) {
            self::assertStringContainsString('only 0 remain', $e->reason);
        }
    }

    public function test_invalid_utf8_in_a_text_string_is_refused(): void
    {
        try {
            // A one-byte text string holding 0xFF, which is not valid UTF-8.
            CborDecoder::decodeAll("\x61\xff");
            self::fail('invalid UTF-8 was accepted');
        } catch (WebAuthnException $e) {
            self::assertStringContainsString('not valid UTF-8', $e->reason);
        }
    }

    // ── The cursor ────────────────────────────────────────────────────────────

    /**
     * The cursor is part of the interface because a COSE key sits inside
     * authenticator data with extension bytes possibly after it, and the caller
     * has to learn where the key ended.
     */
    public function test_the_cursor_reports_how_much_was_consumed(): void
    {
        $decoder = new CborDecoder((string) hex2bin('a201020304') . 'TRAILING');

        self::assertSame([1 => 2, 3 => 4], $decoder->next());
        self::assertSame(5, $decoder->position());
        self::assertFalse($decoder->atEnd());
    }

    public function test_successive_items_can_be_read(): void
    {
        $decoder = new CborDecoder((string) hex2bin('000102'));

        self::assertSame(0, $decoder->next());
        self::assertSame(1, $decoder->next());
        self::assertSame(2, $decoder->next());
        self::assertTrue($decoder->atEnd());
    }
}
