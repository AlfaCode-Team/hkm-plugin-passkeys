<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;

/**
 * The COSE signature algorithms this plugin verifies.
 *
 * WHY THE LIST IS SHORT, AND WHY THAT IS NOT A LIMITATION
 * -------------------------------------------------------
 * COSE registers dozens. Three cover every passkey in existence:
 *
 *   - **ES256** — what every platform authenticator produces. iCloud Keychain,
 *     Google Password Manager, Windows Hello, every FIDO2 key;
 *   - **RS256** — what Windows Hello produced in its TPM-backed era, and still
 *     does on some hardware. Omitting it would reject real users on real
 *     laptops;
 *   - **EdDSA** — Ed25519, some OpenSSH-adjacent and newer keys.
 *
 * The algorithms deliberately absent are the ones that would be dangerous to
 * accept rather than merely unused. `-65535` is RS1 — RSASSA-PKCS1-v1_5 with
 * **SHA-1** — and it is in the COSE registry because old TPMs used it. SHA-1 is
 * broken for collision resistance, and an authenticator offering it is one an
 * application should decline rather than accommodate. There is no `none`
 * algorithm in this enum for the same reason there is no `alg: none` accepted
 * in a JWT library.
 *
 * THE REGISTRATION LIST IS A PREFERENCE ORDER, not a set. The browser picks the
 * first entry the authenticator supports, so ES256 is first: it is universally
 * supported, its signatures are 64 bytes rather than 256, and its keys are
 * cheaper to verify.
 */
enum CoseAlgorithm: int
{
    case ES256 = -7;
    case EdDSA = -8;
    case RS256 = -257;

    /**
     * What to advertise in `pubKeyCredParams`, best first.
     *
     * @return list<self>
     */
    public static function preferred(): array
    {
        return [self::ES256, self::EdDSA, self::RS256];
    }

    public static function fromIdentifier(int $identifier): self
    {
        return self::tryFrom($identifier) ?? throw WebAuthnException::unsupported(
            "COSE algorithm {$identifier} is not supported. "
            . 'Supported: ES256 (-7), EdDSA (-8), RS256 (-257).',
        );
    }

    /** The OpenSSL digest constant, or null for EdDSA which does not take one. */
    public function digest(): ?int
    {
        return match ($this) {
            self::ES256, self::RS256 => OPENSSL_ALGO_SHA256,

            // Ed25519 hashes internally as part of the signature scheme, so
            // there is no separate digest to choose — and it is verified
            // through libsodium rather than OpenSSL for that reason.
            self::EdDSA => null,
        };
    }

    /** The COSE key type (`kty`) this algorithm's keys use. */
    public function keyType(): int
    {
        return match ($this) {
            self::ES256 => 2,   // EC2
            self::RS256 => 3,   // RSA
            self::EdDSA => 1,   // OKP
        };
    }

    public function label(): string
    {
        return $this->name;
    }
}
