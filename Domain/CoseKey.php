<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

use Plugins\Passkeys\Domain\Cbor\CborDecoder;
use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;

/**
 * A credential's public key, as the authenticator sent it, and the one
 * operation that matters: verify a signature with it.
 *
 * A COSE_Key is a CBOR map with negative integer labels, which makes the
 * parsing look cryptic. The labels are from RFC 8152 and are written out at
 * each use below:
 *
 * ```
 *  1  kty   key type        2 = EC2, 3 = RSA, 1 = OKP
 *  3  alg   algorithm       -7 = ES256, -8 = EdDSA, -257 = RS256
 * -1  crv   curve (EC2/OKP) 1 = P-256, 6 = Ed25519
 * -1  n     modulus (RSA)   …the same label means different things per kty
 * -2  x     x coordinate / public key
 * -2  e     exponent (RSA)
 * -3  y     y coordinate (EC2)
 * ```
 *
 * THAT COLLISION IS THE TRAP. `-1` is the curve for an EC2 key and the modulus
 * for an RSA key, and `-2` is a coordinate or an exponent. So the key type has
 * to be established BEFORE any other label is read — a parser that reads `-1`
 * first and asks what it means afterwards can be handed an RSA key that it
 * interprets as a curve identifier.
 *
 * WHAT IS STORED IS THE DER, NOT THE COSE
 * ---------------------------------------
 * {@see self::der()} is what a credential record keeps. Re-deriving it on every
 * sign-in would mean re-running this parser on data from the database on every
 * authentication, and the parser's job is to handle hostile input once, at
 * registration, and then be out of the path.
 */
final readonly class CoseKey
{
    private function __construct(
        public CoseAlgorithm $algorithm,
        /** SubjectPublicKeyInfo DER — what OpenSSL loads, and what is stored. */
        public string $der,
        /** Raw Ed25519 public key, or '' for the OpenSSL-verified algorithms. */
        public string $ed25519,
    ) {}

    /**
     * Parse a COSE_Key and return how many bytes it occupied.
     *
     * The byte count is needed because a COSE key sits inside authenticator
     * data with extensions possibly following it, and the caller has no other
     * way to know where the key ended.
     *
     * @return array{0: self, 1: int} the key, and the offset just past it
     */
    public static function parse(string $bytes, int $offset = 0): array
    {
        $decoder = new CborDecoder(substr($bytes, $offset));
        $map     = $decoder->next();

        if (!\is_array($map)) {
            throw WebAuthnException::malformed('The credential public key is not a CBOR map.');
        }

        // kty first, always. See the class docblock.
        $keyType   = self::integer($map, 1, 'key type');
        $algorithm = CoseAlgorithm::fromIdentifier(self::integer($map, 3, 'algorithm'));

        if ($keyType !== $algorithm->keyType()) {
            throw WebAuthnException::rejected(
                "The key type ({$keyType}) does not match the algorithm {$algorithm->label()}.",
            );
        }

        $key = match ($algorithm) {
            CoseAlgorithm::ES256 => self::fromEc2($map, $algorithm),
            CoseAlgorithm::RS256 => self::fromRsa($map, $algorithm),
            CoseAlgorithm::EdDSA => self::fromOkp($map, $algorithm),
        };

        return [$key, $offset + $decoder->position()];
    }

    /** Rebuild from a stored DER, with no parsing of untrusted input. */
    public static function fromStored(string $der, CoseAlgorithm $algorithm, string $ed25519 = ''): self
    {
        return new self($algorithm, $der, $ed25519);
    }

    /**
     * Whether $signature is a valid signature over $data.
     *
     * Returns false rather than throwing for a bad signature, because a wrong
     * signature is the expected outcome of an attempt by someone who does not
     * hold the key — the routine case, not an error.
     */
    public function verify(string $data, string $signature): bool
    {
        if ($signature === '') {
            return false;
        }

        if ($this->algorithm === CoseAlgorithm::EdDSA) {
            return $this->verifyEd25519($data, $signature);
        }

        $publicKey = openssl_pkey_get_public(Der::toPem($this->der));

        if ($publicKey === false) {
            // The DER was built by this class and stored by this plugin, so
            // reaching here means the record is corrupt rather than that the
            // signature is wrong. Still false: a credential whose key cannot be
            // loaded must not authenticate anyone.
            return false;
        }

        $digest = $this->algorithm->digest();

        // openssl_verify returns 1, 0 or -1. The !== 1 comparison is deliberate:
        // -1 means an OpenSSL-level error, and `=== 0` or a truthiness check
        // would read an error as a clean rejection — or, worse, a `!= 0` check
        // would read it as a VALID signature.
        return openssl_verify($data, $signature, $publicKey, $digest ?? OPENSSL_ALGO_SHA256) === 1;
    }

    private function verifyEd25519(string $data, string $signature): bool
    {
        // Ed25519 signatures are exactly 64 bytes and the public key 32.
        // sodium_crypto_sign_verify_detached THROWS on a wrong length rather
        // than returning false, so the lengths are checked first — an
        // exception here would escape as a 500 on what is simply an invalid
        // credential.
        if (\strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES
            || \strlen($this->ed25519) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $data, $this->ed25519);
    }

    /**
     * EC2: `ASN.1 SubjectPublicKeyInfo { AlgorithmIdentifier, BIT STRING }`
     * where the bit string is the uncompressed point `0x04 ‖ x ‖ y`.
     *
     * @param array<int|string, mixed> $map
     */
    private static function fromEc2(array $map, CoseAlgorithm $algorithm): self
    {
        $curve = self::integer($map, -1, 'curve');

        // 1 is P-256. ES256 is DEFINED as P-256 with SHA-256, so any other
        // curve with this algorithm is a contradiction rather than an
        // unsupported combination — accepting it would mean verifying with a
        // digest the curve was not paired with.
        if ($curve !== 1) {
            throw WebAuthnException::unsupported(
                "COSE curve {$curve} is not supported; ES256 requires P-256 (curve 1).",
            );
        }

        $x = self::bytes($map, -2, 'x coordinate');
        $y = self::bytes($map, -3, 'y coordinate');

        // Exactly 32 bytes each on P-256. A short coordinate would otherwise be
        // silently left-padded by the point encoding and verify against a
        // DIFFERENT key than the authenticator holds.
        if (\strlen($x) !== 32 || \strlen($y) !== 32) {
            throw WebAuthnException::malformed(
                'A P-256 coordinate must be 32 bytes; got ' . \strlen($x) . ' and ' . \strlen($y) . '.',
            );
        }

        $der = Der::sequence(
            Der::sequence(
                Der::oid('1.2.840.10045.2.1'),      // id-ecPublicKey
                Der::oid('1.2.840.10045.3.1.7'),    // prime256v1 (P-256)
            ),
            Der::bitString("\x04" . $x . $y),       // 0x04 = uncompressed point
        );

        return new self($algorithm, $der, '');
    }

    /**
     * RSA: `SubjectPublicKeyInfo` whose bit string wraps
     * `RSAPublicKey { INTEGER n, INTEGER e }`.
     *
     * @param array<int|string, mixed> $map
     */
    private static function fromRsa(array $map, CoseAlgorithm $algorithm): self
    {
        $modulus  = ltrim(self::bytes($map, -1, 'modulus'), "\x00");
        $exponent = ltrim(self::bytes($map, -2, 'exponent'), "\x00");

        // 2048 bits is the floor anything current should be using, and a short
        // modulus is the one property of an offered key that an application can
        // check cheaply and should.
        if (\strlen($modulus) < 256) {
            throw WebAuthnException::rejected(
                'The RSA modulus is ' . (\strlen($modulus) * 8) . ' bits; at least 2048 are required.',
            );
        }

        // An upper bound as well. OpenSSL refuses a modulus over 16384 bits for
        // any operation, so a larger one cannot authenticate anybody — but it
        // can be stored, and a modular exponentiation grows with the square of
        // the modulus, so an absurd key is a way to buy CPU on every attempt.
        if (\strlen($modulus) > 1024) {
            throw WebAuthnException::rejected(
                'The RSA modulus is ' . (\strlen($modulus) * 8) . ' bits; at most 8192 are accepted.',
            );
        }

        self::assertUsableExponent($exponent);

        $der = Der::sequence(
            Der::sequence(
                Der::oid('1.2.840.113549.1.1.1'),   // rsaEncryption
                Der::null(),                        // absent parameters, explicitly NULL
            ),
            Der::bitString(Der::sequence(
                Der::unsignedInteger($modulus),
                Der::unsignedInteger($exponent),
            )),
        );

        return new self($algorithm, $der, '');
    }

    /**
     * OKP (Ed25519): no DER is built, because the key is verified through
     * libsodium and the raw 32 bytes are all it needs.
     *
     * @param array<int|string, mixed> $map
     */
    private static function fromOkp(array $map, CoseAlgorithm $algorithm): self
    {
        $curve = self::integer($map, -1, 'curve');

        if ($curve !== 6) {
            throw WebAuthnException::unsupported(
                "COSE curve {$curve} is not supported; EdDSA here requires Ed25519 (curve 6).",
            );
        }

        $publicKey = self::bytes($map, -2, 'public key');

        if (\strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw WebAuthnException::malformed(
                'An Ed25519 public key must be ' . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
                . ' bytes; got ' . \strlen($publicKey) . '.',
            );
        }

        return new self($algorithm, $publicKey, $publicKey);
    }

    /**
     * The RSA public exponent has to be checked, and OpenSSL will not do it.
     *
     * THIS IS NOT HARDENING. A key with `e = 1` makes signature verification
     * `s¹ mod n == padded_digest`, so the signature IS the padded digest and
     * anyone can compute one with no private key at all. An even exponent is
     * not an RSA exponent — it shares a factor with φ(n), so no inverse exists
     * and the scheme is simply broken.
     *
     * Both were measured against this build rather than assumed:
     * `openssl_pkey_get_public()` LOADS an `e = 1` SubjectPublicKeyInfo without
     * complaint, and `openssl_verify()` then returns 1 for a forged signature.
     * OpenSSL applies the exponent rules when it GENERATES a key and when a
     * caller explicitly validates one; it does not apply them on import, and
     * nothing in a verification path calls the validator.
     *
     * So a credential registered with such a key would authenticate anyone who
     * knew its credential id — and the credential id is not a secret: it is
     * handed to the browser in `excludeCredentials` and listed by
     * `GET /auth/passkeys`. Registration requires a session, so planting one
     * needs a foothold; what the check removes is the ability to turn that
     * foothold into a permanent credential that needs no private key.
     *
     * The bounds are NIST SP 800-56B's: odd, and 2¹⁶ < e < 2²⁵⁶. Every
     * authenticator in existence uses 65537, so the floor costs nothing real,
     * and the ceiling keeps the verification exponentiation cheap.
     */
    private static function assertUsableExponent(string $exponent): void
    {
        $length = \strlen($exponent);

        if ($length === 0 || $length > 32) {
            throw WebAuthnException::rejected(
                'The RSA public exponent is ' . ($length * 8) . ' bits; it must be between 17 and 256.',
            );
        }

        // An even exponent cannot be an RSA exponent at all.
        if ((\ord($exponent[$length - 1]) & 1) === 0) {
            throw WebAuthnException::rejected('The RSA public exponent is even, so the key is unusable.');
        }

        // Greater than 2^16, i.e. at least three bytes. Two bytes or fewer is
        // at most 65535, which excludes 1 and 3 along with everything else
        // below the standard floor.
        if ($length < 3) {
            throw WebAuthnException::rejected(
                'The RSA public exponent is too small; at least 65537 is required. '
                . 'A tiny exponent makes signatures forgeable without the private key.',
            );
        }
    }

    /** @param array<int|string, mixed> $map */
    private static function integer(array $map, int $label, string $what): int
    {
        $value = $map[$label] ?? null;

        if (!\is_int($value)) {
            throw WebAuthnException::malformed("The credential public key has no integer {$what}.");
        }

        return $value;
    }

    /** @param array<int|string, mixed> $map */
    private static function bytes(array $map, int $label, string $what): string
    {
        $value = $map[$label] ?? null;

        if (!\is_string($value) || $value === '') {
            throw WebAuthnException::malformed("The credential public key has no {$what}.");
        }

        return $value;
    }
}
