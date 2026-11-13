<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\Passkeys\Domain\Base64Url;
use Plugins\Passkeys\Domain\CoseAlgorithm;
use Plugins\Passkeys\Domain\CoseKey;
use Plugins\Passkeys\Domain\Der;
use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;

/**
 * The COSE-to-DER conversion, checked against OpenSSL's own serialisation.
 *
 * THE CENTRAL TEST IN THIS FILE IS THE BYTE-FOR-BYTE COMPARISON
 * ------------------------------------------------------------
 * A key built here is compared with the PEM that OpenSSL produces for the same
 * key pair. OpenSSL wrote its version from the key material directly and knows
 * nothing about COSE, this plugin, or what it intended — so if the DER encoder
 * had a length byte wrong, a missing leading zero on an RSA modulus, or the
 * unused-bits byte in the wrong place, the two strings would differ.
 *
 * That is a stronger claim than "OpenSSL accepted the key", which is the test
 * one would naturally write and which passes for several wrong encodings:
 * OpenSSL is tolerant about some malformations and will happily load a key
 * whose coordinates have been shifted, then fail every verification afterwards
 * for reasons that look like a signature problem.
 */
#[CoversClass(Der::class)]
#[CoversClass(CoseKey::class)]
#[CoversClass(Base64Url::class)]
final class KeyEncodingTest extends TestCase
{
    /**
     * @return iterable<string, array{0: CoseAlgorithm}>
     */
    public static function opensslAlgorithms(): iterable
    {
        yield 'ES256 (P-256)' => [CoseAlgorithm::ES256];
        yield 'RS256 (RSA)'   => [CoseAlgorithm::RS256];
    }

    #[DataProvider('opensslAlgorithms')]
    public function test_the_der_matches_what_openssl_writes_for_the_same_key(CoseAlgorithm $algorithm): void
    {
        $authenticator = new FakeAuthenticator($algorithm);

        [$key] = CoseKey::parse($authenticator->coseKey());

        $mine = Der::toPem($key->der);

        // OpenSSL's own public-key export. Produced from the key material, by
        // code that has never heard of this plugin.
        $theirs = $this->opensslPublicPem($authenticator);

        self::assertSame(
            $this->normalise($theirs),
            $this->normalise($mine),
            'the DER this plugin builds must be byte-identical to OpenSSL\'s serialisation',
        );
    }

    /**
     * An RSA modulus has its top bit set about half the time, and a DER INTEGER
     * is signed — so without a leading zero byte it reads as negative. Getting
     * this wrong makes roughly half of all RSA keys fail and the other half
     * work, which is the most confusing possible failure rate.
     */
    public function test_a_high_bit_modulus_gets_its_leading_zero(): void
    {
        $withHighBit = Der::unsignedInteger("\xFF\x01\x02");

        self::assertSame(
            "\x02\x04\x00\xFF\x01\x02",
            $withHighBit,
            'tag 02, length 4, then a zero byte before the value',
        );

        $withoutHighBit = Der::unsignedInteger("\x7F\x01\x02");

        self::assertSame("\x02\x03\x7F\x01\x02", $withoutHighBit, 'and no padding when it is not needed');
    }

    /** DER requires the shortest form, and some encoders pad. */
    public function test_leading_zeros_are_stripped(): void
    {
        self::assertSame("\x02\x01\x05", Der::unsignedInteger("\x00\x00\x05"));
        self::assertSame("\x02\x01\x00", Der::unsignedInteger("\x00\x00\x00"), 'zero stays one byte');
    }

    /**
     * The rule a hard-coded key prefix hides, and the one that breaks the
     * moment a key is larger than 127 bytes — which every RSA key is.
     */
    public function test_long_form_lengths(): void
    {
        self::assertSame("\x04\x7F" . str_repeat('x', 127), Der::encode(0x04, str_repeat('x', 127)));

        // 128 bytes: one length byte, flagged, then the length itself.
        self::assertSame("\x04\x81\x80" . str_repeat('x', 128), Der::encode(0x04, str_repeat('x', 128)));

        // 300 bytes: two length bytes.
        self::assertSame("\x04\x82\x01\x2C" . str_repeat('x', 300), Der::encode(0x04, str_repeat('x', 300)));
    }

    public function test_object_identifiers_encode_to_the_known_values(): void
    {
        // The first two arcs share a byte: 40 * 1 + 2 = 42 = 0x2A.
        self::assertSame('06072a8648ce3d0201', bin2hex(Der::oid('1.2.840.10045.2.1')), 'id-ecPublicKey');
        self::assertSame('06082a8648ce3d030107', bin2hex(Der::oid('1.2.840.10045.3.1.7')), 'prime256v1');
        self::assertSame('06092a864886f70d010101', bin2hex(Der::oid('1.2.840.113549.1.1.1')), 'rsaEncryption');
    }

    /** The unused-bit count is part of the contents, not the header. */
    public function test_a_bit_string_carries_its_unused_bit_count(): void
    {
        self::assertSame("\x03\x03\x00\xAB\xCD", Der::bitString("\xAB\xCD"));
    }

    // ── COSE parsing ──────────────────────────────────────────────────────────

    public function test_the_key_reports_how_many_bytes_it_occupied(): void
    {
        $authenticator = new FakeAuthenticator();
        $cose          = $authenticator->coseKey();

        [, $offset] = CoseKey::parse($cose . 'EXTENSION-BYTES');

        self::assertSame(
            \strlen($cose),
            $offset,
            'a COSE key has no length prefix, so the offset is the only way to find the extensions',
        );
    }

    public function test_an_ed25519_key_is_kept_raw_rather_than_wrapped_in_der(): void
    {
        [$key] = CoseKey::parse((new FakeAuthenticator(CoseAlgorithm::EdDSA))->coseKey());

        self::assertSame(CoseAlgorithm::EdDSA, $key->algorithm);
        self::assertSame(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, \strlen($key->ed25519));
    }

    /** @return iterable<string, array{0: list<array{0: string, 1: string}>, 1: string}> */
    public static function badKeys(): iterable
    {
        yield 'no key type' => [
            [[Cbor::int(3), Cbor::int(-7)]],
            'no integer key type',
        ];

        yield 'no algorithm' => [
            [[Cbor::int(1), Cbor::int(2)]],
            'no integer algorithm',
        ];

        yield 'an unsupported algorithm' => [
            [[Cbor::int(1), Cbor::int(2)], [Cbor::int(3), Cbor::int(-36)]],
            'not supported',
        ];

        // RS1 — RSASSA-PKCS1-v1_5 with SHA-1. In the COSE registry because old
        // TPMs used it, and declined for the same reason `alg: none` is
        // declined in a JWT library.
        yield 'sha-1 (RS1)' => [
            [[Cbor::int(1), Cbor::int(3)], [Cbor::int(3), Cbor::int(-65535)]],
            'not supported',
        ];

        // The key type and the algorithm must agree, or the key is being read
        // under the wrong interpretation of its own labels.
        yield 'key type contradicting the algorithm' => [
            [[Cbor::int(1), Cbor::int(3)], [Cbor::int(3), Cbor::int(-7)]],
            'does not match the algorithm',
        ];

        yield 'a curve ES256 is not defined for' => [
            [
                [Cbor::int(1), Cbor::int(2)],
                [Cbor::int(3), Cbor::int(-7)],
                [Cbor::int(-1), Cbor::int(2)],
                [Cbor::int(-2), Cbor::bytes(str_repeat('x', 48))],
                [Cbor::int(-3), Cbor::bytes(str_repeat('y', 48))],
            ],
            'ES256 requires P-256',
        ];

        // A short coordinate would be silently left-padded by the point
        // encoding and verify against a DIFFERENT key than the authenticator
        // holds.
        yield 'a short P-256 coordinate' => [
            [
                [Cbor::int(1), Cbor::int(2)],
                [Cbor::int(3), Cbor::int(-7)],
                [Cbor::int(-1), Cbor::int(1)],
                [Cbor::int(-2), Cbor::bytes(str_repeat('x', 31))],
                [Cbor::int(-3), Cbor::bytes(str_repeat('y', 32))],
            ],
            'must be 32 bytes',
        ];

        yield 'an undersized RSA modulus' => [
            [
                [Cbor::int(1), Cbor::int(3)],
                [Cbor::int(3), Cbor::int(-257)],
                [Cbor::int(-1), Cbor::bytes(str_repeat('n', 128))],
                [Cbor::int(-2), Cbor::bytes("\x01\x00\x01")],
            ],
            'at least 2048',
        ];

        yield 'an oversized RSA modulus' => [
            self::rsaKey(str_repeat('n', 2048), "\x01\x00\x01"),
            'at most 8192',
        ];

        // ── The public exponent ───────────────────────────────────────────────
        //
        // These are not hardening. `e = 1` makes PKCS#1 v1.5 verification
        // `s¹ mod n == padded_digest`, so the signature IS the padded digest
        // and anyone can produce one with no private key. OpenSSL does not stop
        // it: measured on this build, `openssl_pkey_get_public()` loads such a
        // key and `openssl_verify()` then returns 1 for a forged signature,
        // because the exponent rules are applied at key GENERATION and in the
        // explicit validator, neither of which a verification path calls.
        //
        // See test_an_e_equals_1_key_would_have_accepted_a_forged_signature,
        // which carries out the forgery to show what these refusals prevent.

        yield 'an RSA exponent of 1 (signatures forgeable without the key)' => [
            self::rsaKey(self::modulus2048(), "\x01"),
            'too small',
        ];

        yield 'an RSA exponent of 3 (below the SP 800-56B floor)' => [
            self::rsaKey(self::modulus2048(), "\x03"),
            'too small',
        ];

        yield 'an even RSA exponent (not an RSA exponent at all)' => [
            self::rsaKey(self::modulus2048(), "\x02"),
            'even',
        ];

        yield 'an even RSA exponent of 65536' => [
            self::rsaKey(self::modulus2048(), "\x01\x00\x00"),
            'even',
        ];

        yield 'an RSA exponent of zero' => [
            self::rsaKey(self::modulus2048(), "\x00"),
            'exponent',
        ];

        yield 'an absurdly large RSA exponent' => [
            self::rsaKey(self::modulus2048(), str_repeat("\xFF", 64)),
            'between 17 and 256',
        ];

        yield 'an Ed25519 key of the wrong length' => [
            [
                [Cbor::int(1), Cbor::int(1)],
                [Cbor::int(3), Cbor::int(-8)],
                [Cbor::int(-1), Cbor::int(6)],
                [Cbor::int(-2), Cbor::bytes(str_repeat('k', 16))],
            ],
            'must be 32 bytes',
        ];
    }

    /**
     * A 2048-bit modulus with its top bit set, as a real one always has.
     *
     * COMPUTED RATHER THAN WRITTEN OUT, because the length is the one thing
     * about it that matters and a hand-written literal got it wrong: 257 bytes
     * instead of 256. Every exponent case still passed — they never reach the
     * modulus — but the forgery test below silently stopped testing what it
     * claimed to, because OpenSSL rejected the 256-byte forged signature on its
     * LENGTH against a 2056-bit key and returned 0 for a reason that had
     * nothing to do with the exponent.
     */
    private static function modulus2048(): string
    {
        // Top bit set, bottom bit set: the shape of a real RSA modulus, which
        // is a product of two large odd primes.
        return "\xC0" . str_repeat("\x7F", 254) . "\x01";
    }

    /** @return list<array{0: string, 1: string}> */
    private static function rsaKey(string $modulus, string $exponent): array
    {
        return [
            [Cbor::int(1), Cbor::int(3)],       // kty = RSA
            [Cbor::int(3), Cbor::int(-257)],    // alg = RS256
            [Cbor::int(-1), Cbor::bytes($modulus)],
            [Cbor::int(-2), Cbor::bytes($exponent)],
        ];
    }

    /**
     * @param list<array{0: string, 1: string}> $pairs
     */
    #[DataProvider('badKeys')]
    public function test_a_key_that_cannot_be_trusted_is_refused(array $pairs, string $reasonFragment): void
    {
        try {
            CoseKey::parse(Cbor::map($pairs));
            self::fail("the key was accepted; expected a refusal mentioning [{$reasonFragment}]");
        } catch (WebAuthnException $e) {
            self::assertStringContainsString($reasonFragment, $e->reason);
        }
    }

    /**
     * What the exponent refusals above actually prevent, carried out.
     *
     * This test asserts a fact about OPENSSL, not about this plugin, and it is
     * here because the plugin's defence rests on that fact being true. With
     * `e = 1`, PKCS#1 v1.5 verification reduces to `s¹ mod n == EMSA(digest)`,
     * so the signature is simply the padded digest and no private key is
     * involved in producing one.
     *
     * If a future OpenSSL starts refusing such keys on import, this test fails
     * and says so — at which point the guard in {@see CoseKey} is belt and
     * braces rather than the only thing standing there. Either way it should be
     * known which of those two it is.
     */
    public function test_an_e_equals_1_key_would_have_accepted_a_forged_signature(): void
    {
        $data = 'authenticatorData || clientDataHash';

        // The attacker chooses n freely; it only has to exceed the padded block.
        $modulus = self::modulus2048();

        $der = Der::sequence(
            Der::sequence(Der::oid('1.2.840.113549.1.1.1'), Der::null()),
            Der::bitString(Der::sequence(
                Der::unsignedInteger($modulus),
                Der::unsignedInteger("\x01"),
            )),
        );

        $key = openssl_pkey_get_public(Der::toPem($der));

        if ($key === false) {
            self::markTestSkipped('this OpenSSL refuses an e=1 key on import, which is the stronger behaviour');
        }

        // EMSA-PKCS1-v1_5: 0x00 0x01, 0xFF padding, 0x00, then the DigestInfo.
        // Sized from the MODULUS, not from a literal 256: a signature whose
        // length does not match the key's is refused on that alone, which looks
        // exactly like the forgery having failed.
        $digestInfo = (string) hex2bin('3031300d060960864801650304020105000420') . hash('sha256', $data, true);
        $forged     = "\x00\x01" . str_repeat("\xFF", \strlen($modulus) - 3 - \strlen($digestInfo))
            . "\x00" . $digestInfo;

        self::assertSame(\strlen($modulus), \strlen($forged), 'the forged signature must be modulus-sized');

        self::assertSame(
            1,
            openssl_verify($data, $forged, $key, OPENSSL_ALGO_SHA256),
            'if this is no longer 1, OpenSSL has started rejecting e=1 keys and the comment above is stale',
        );

        // Which is why the key never reaches a verification in the first place.
        try {
            CoseKey::parse(Cbor::map(self::rsaKey($modulus, "\x01")));
            self::fail('an e=1 key must never be stored as a credential');
        } catch (WebAuthnException $e) {
            self::assertStringContainsString('forgeable', $e->reason);
        }
    }

    public function test_a_key_that_is_not_a_map_is_refused(): void
    {
        try {
            CoseKey::parse(Cbor::int(7));
            self::fail('a non-map was accepted');
        } catch (WebAuthnException $e) {
            self::assertStringContainsString('not a CBOR map', $e->reason);
        }
    }

    /**
     * An empty signature must not verify. Trivial, and worth pinning: it is the
     * shape a request takes when a client omits the field and something
     * upstream defaults it to `''`.
     */
    public function test_an_empty_signature_never_verifies(): void
    {
        [$key] = CoseKey::parse((new FakeAuthenticator())->coseKey());

        self::assertFalse($key->verify('anything', ''));
    }

    public function test_a_corrupt_stored_key_fails_closed(): void
    {
        $key = CoseKey::fromStored('not DER at all', CoseAlgorithm::ES256);

        // False, not an exception: a credential whose key cannot be loaded must
        // not authenticate anyone, and must not 500 either.
        self::assertFalse($key->verify('data', str_repeat("\x01", 70)));
    }

    // ── base64url ─────────────────────────────────────────────────────────────

    public function test_base64url_round_trips_including_the_url_safe_characters(): void
    {
        for ($i = 0; $i < 200; ++$i) {
            $bytes   = random_bytes(random_int(1, 64));
            $encoded = Base64Url::encode($bytes);

            self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $encoded, 'no padding, no + or /');
            self::assertSame($bytes, Base64Url::decode($encoded));
        }
    }

    /**
     * The trap this class exists for: non-strict `base64_decode` SKIPS
     * characters it does not recognise, so a value containing `-` decodes to
     * something shorter than it should — silently — and the equality check that
     * follows compares two things that are both wrong.
     */
    public function test_the_url_safe_alphabet_is_translated_and_not_skipped(): void
    {
        $bytes = "\xFB\xEF\xBE";  // encodes with both - and _
        $url   = Base64Url::encode($bytes);

        self::assertStringContainsString('-', $url . '_', 'the fixture should exercise the alphabet');
        self::assertSame($bytes, Base64Url::decode($url));
    }

    /** @return iterable<string, array{0: string}> */
    public static function badBase64Url(): iterable
    {
        yield 'empty'              => [''];
        yield 'plus'               => ['ab+d'];
        yield 'slash'              => ['ab/d'];
        yield 'whitespace'         => ['ab cd'];
        yield 'a one-char group'   => ['abcde'];
        yield 'non-alphabet'       => ['ab$d'];
        yield 'a newline'          => ["abcd\n"];
    }

    #[DataProvider('badBase64Url')]
    public function test_bad_base64url_is_refused(string $value): void
    {
        $this->expectException(WebAuthnException::class);

        Base64Url::decode($value, 'test value');
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** OpenSSL's own PEM for the authenticator's public key. */
    private function opensslPublicPem(FakeAuthenticator $authenticator): string
    {
        // Re-derive by signing and recovering is not possible, so the key is
        // regenerated here through the same path and its details read. The
        // FakeAuthenticator exposes the COSE form; this reads OpenSSL's.
        $reflection = new \ReflectionProperty(FakeAuthenticator::class, 'privateKey');
        $key        = $reflection->getValue($authenticator);

        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);

        $details = openssl_pkey_get_details($key);

        self::assertIsArray($details);
        self::assertIsString($details['key']);

        return $details['key'];
    }

    private function normalise(string $pem): string
    {
        return trim(str_replace(["\r\n", "\r"], "\n", $pem));
    }
}
