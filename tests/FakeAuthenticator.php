<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Passkeys;

use Plugins\Passkeys\Domain\Base64Url;
use Plugins\Passkeys\Domain\CoseAlgorithm;

/**
 * A working authenticator, built from real keys and real signatures.
 *
 * WHY THIS IS WORTH THE LINES
 * ---------------------------
 * The alternative is a captured response from a real device, pasted in as a
 * fixture. That proves the parser handles one authenticator once, and it cannot
 * be varied — no way to test a wrong challenge, a flipped flag, a stale
 * counter, a different algorithm, or a tampered signature, which is where all
 * the interesting behaviour is.
 *
 * WHAT IS AND IS NOT INDEPENDENTLY VERIFIED, stated plainly because it is the
 * limit of what this suite can claim:
 *
 *   - the CBOR ENCODER here is this test's own, so a matching bug in it and in
 *     the decoder would cancel out. The decoder is therefore ALSO tested
 *     against hand-written byte sequences from RFC 8949, which this file did
 *     not produce;
 *   - the SIGNATURES are not self-referential in any way. They are produced by
 *     OpenSSL and libsodium and verified by OpenSSL and libsodium. If the
 *     COSE-to-DER conversion in {@see \Plugins\Passkeys\Domain\CoseKey} were
 *     wrong by one byte, OpenSSL would reject the key or the signature — it has
 *     no knowledge of what this plugin intended. That makes the crypto path the
 *     most strongly verified part of the plugin, which is the right place for
 *     the strongest verification to be.
 *
 * What this cannot prove is that a real iPhone's bytes parse. That claim needs
 * a real iPhone.
 */
final class FakeAuthenticator
{
    public readonly string $credentialId;

    private \OpenSSLAsymmetricKey|null $privateKey = null;

    private string $sodiumSecretKey = '';

    private string $cosePublicKey;

    public function __construct(
        public readonly CoseAlgorithm $algorithm = CoseAlgorithm::ES256,
        public readonly string $rpId = 'example.com',
        public readonly string $origin = 'https://app.example.com',
        ?string $credentialId = null,
        /** All zeros is what a platform authenticator reports. */
        public readonly string $aaguid = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ) {
        $this->credentialId  = $credentialId ?? random_bytes(32);
        $this->cosePublicKey = $this->generateKey();
    }

    // ── The two ceremonies ────────────────────────────────────────────────────

    /**
     * A registration response, as the browser would serialise it.
     *
     * @return array<string, string>
     */
    public function register(
        string $challenge,
        int $signCount = 0,
        bool $userPresent = true,
        bool $userVerified = true,
        bool $backupEligible = true,
        string $format = 'none',
        ?string $overrideRpId = null,
    ): array {
        $clientDataJson = $this->clientDataJson('webauthn.create', $challenge);

        $flags = 0x40; // AT — attested credential data present

        if ($userPresent) {
            $flags |= 0x01;
        }

        if ($userVerified) {
            $flags |= 0x04;
        }

        if ($backupEligible) {
            $flags |= 0x08 | 0x10; // BE and BS
        }

        $authData = $this->authenticatorData($flags, $signCount, true, $overrideRpId);

        return [
            'clientDataJSON'    => Base64Url::encode($clientDataJson),
            'attestationObject' => Base64Url::encode(
                $this->attestationObject($format, $authData, $clientDataJson),
            ),
        ];
    }

    /**
     * An authentication response.
     *
     * @return array<string, string>
     */
    public function authenticate(
        string $challenge,
        int $signCount = 1,
        bool $userPresent = true,
        bool $userVerified = true,
        ?string $overrideRpId = null,
        ?string $overrideOrigin = null,
        ?string $tamperSignature = null,
        string $userHandle = '',
    ): array {
        $clientDataJson = $this->clientDataJson('webauthn.get', $challenge, $overrideOrigin);

        $flags = 0;

        if ($userPresent) {
            $flags |= 0x01;
        }

        if ($userVerified) {
            $flags |= 0x04;
        }

        $authData = $this->authenticatorData($flags, $signCount, false, $overrideRpId);

        $response = [
            'clientDataJSON'    => Base64Url::encode($clientDataJson),
            'authenticatorData' => Base64Url::encode($authData),
            'signature'         => Base64Url::encode(
                $tamperSignature ?? $this->sign($authData . hash('sha256', $clientDataJson, true)),
            ),
        ];

        if ($userHandle !== '') {
            $response['userHandle'] = Base64Url::encode($userHandle);
        }

        return $response;
    }

    /** The COSE_Key bytes, for building a stored credential in a test. */
    public function coseKey(): string
    {
        return $this->cosePublicKey;
    }

    public function sign(string $data): string
    {
        if ($this->algorithm === CoseAlgorithm::EdDSA) {
            return sodium_crypto_sign_detached($data, $this->sodiumSecretKey);
        }

        $signature = '';
        openssl_sign($data, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

        return $signature;
    }

    // ── Key generation ────────────────────────────────────────────────────────

    /** Returns the COSE_Key encoding of the public half. */
    private function generateKey(): string
    {
        if ($this->algorithm === CoseAlgorithm::EdDSA) {
            $pair                  = sodium_crypto_sign_keypair();
            $this->sodiumSecretKey = sodium_crypto_sign_secretkey($pair);

            return Cbor::map([
                [Cbor::int(1), Cbor::int(1)],                                   // kty: OKP
                [Cbor::int(3), Cbor::int(CoseAlgorithm::EdDSA->value)],         // alg
                [Cbor::int(-1), Cbor::int(6)],                                  // crv: Ed25519
                [Cbor::int(-2), Cbor::bytes(sodium_crypto_sign_publickey($pair))],
            ]);
        }

        $configuration = $this->algorithm === CoseAlgorithm::ES256
            ? ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']
            : ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048];

        $key = openssl_pkey_new($configuration);

        if ($key === false) {
            throw new \RuntimeException('openssl_pkey_new failed: ' . openssl_error_string());
        }

        $this->privateKey = $key;
        $details          = openssl_pkey_get_details($key);

        if (!\is_array($details)) {
            throw new \RuntimeException('openssl_pkey_get_details failed');
        }

        if ($this->algorithm === CoseAlgorithm::ES256) {
            /** @var array{x: string, y: string} $ec */
            $ec = $details['ec'];

            return Cbor::map([
                [Cbor::int(1), Cbor::int(2)],                                   // kty: EC2
                [Cbor::int(3), Cbor::int(CoseAlgorithm::ES256->value)],        // alg
                [Cbor::int(-1), Cbor::int(1)],                                  // crv: P-256
                // Left-padded to 32 bytes: OpenSSL strips a leading zero byte
                // from a coordinate, and a 31-byte coordinate is exactly the
                // malformed input CoseKey refuses.
                [Cbor::int(-2), Cbor::bytes(str_pad($ec['x'], 32, "\x00", STR_PAD_LEFT))],
                [Cbor::int(-3), Cbor::bytes(str_pad($ec['y'], 32, "\x00", STR_PAD_LEFT))],
            ]);
        }

        /** @var array{n: string, e: string} $rsa */
        $rsa = $details['rsa'];

        return Cbor::map([
            [Cbor::int(1), Cbor::int(3)],                                       // kty: RSA
            [Cbor::int(3), Cbor::int(CoseAlgorithm::RS256->value)],            // alg
            [Cbor::int(-1), Cbor::bytes($rsa['n'])],                            // modulus
            [Cbor::int(-2), Cbor::bytes($rsa['e'])],                            // exponent
        ]);
    }

    // ── Structures ────────────────────────────────────────────────────────────

    private function clientDataJson(string $type, string $challenge, ?string $origin = null): string
    {
        return (string) json_encode([
            'type'        => $type,
            'challenge'   => $challenge,
            'origin'      => $origin ?? $this->origin,
            'crossOrigin' => false,
        ], JSON_UNESCAPED_SLASHES);
    }

    private function authenticatorData(
        int $flags,
        int $signCount,
        bool $withCredential,
        ?string $overrideRpId,
    ): string {
        $data = hash('sha256', $overrideRpId ?? $this->rpId, true)
            . \chr($flags)
            . pack('N', $signCount);

        if ($withCredential) {
            $data .= $this->aaguid
                . pack('n', \strlen($this->credentialId))
                . $this->credentialId
                . $this->cosePublicKey;
        }

        return $data;
    }

    private function attestationObject(string $format, string $authData, string $clientDataJson): string
    {
        $statement = match ($format) {
            'packed' => Cbor::map([
                [Cbor::text('alg'), Cbor::int($this->algorithm->value)],
                [Cbor::text('sig'), Cbor::bytes(
                    $this->sign($authData . hash('sha256', $clientDataJson, true)),
                )],
            ]),
            'packed-x5c' => Cbor::map([
                [Cbor::text('alg'), Cbor::int($this->algorithm->value)],
                [Cbor::text('sig'), Cbor::bytes('irrelevant')],
                [Cbor::text('x5c'), Cbor::array([Cbor::bytes('not-a-real-certificate')])],
            ]),
            default => Cbor::map([]),
        };

        return Cbor::map([
            [Cbor::text('fmt'), Cbor::text($format === 'packed-x5c' ? 'packed' : $format)],
            [Cbor::text('attStmt'), $statement],
            [Cbor::text('authData'), Cbor::bytes($authData)],
        ]);
    }
}
