<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;

/**
 * The authenticator's own signed statement.
 *
 * ```
 *  32  rpIdHash            sha256 of the relying party id
 *   1  flags               UP | – | UV | BE | BS | – | AT | ED
 *   4  signCount           big-endian
 *      ─ if AT ─
 *  16  aaguid              the authenticator model, or all zeros
 *   2  credentialIdLength  big-endian
 *   …  credentialId
 *   …  credentialPublicKey COSE_Key, variable length
 *      ─ if ED ─
 *   …  extensions          CBOR map
 * ```
 *
 * THE VARIABLE-LENGTH KEY IS WHY THIS CANNOT BE A SINGLE `unpack()`. The COSE
 * key has no length prefix, so the only way to find the extensions is to parse
 * the key and ask where it ended — which is why
 * {@see CoseKey::parse()} returns an offset.
 *
 * `rpIdHash` IS A HASH, NOT A NAME, and the check against it is the reason a
 * credential registered for one site cannot be replayed at another. It is also
 * why an application's relying party id must never change: every existing
 * credential's rpIdHash was computed from the old one, so changing it
 * invalidates every passkey at once, silently, with the symptom "nobody can log
 * in".
 */
final readonly class AuthenticatorData
{
    public const FLAG_USER_PRESENT          = 0x01;
    public const FLAG_USER_VERIFIED         = 0x04;
    public const FLAG_BACKUP_ELIGIBLE       = 0x08;
    public const FLAG_BACKED_UP             = 0x10;
    public const FLAG_ATTESTED_CREDENTIAL   = 0x40;
    public const FLAG_EXTENSION_DATA        = 0x80;

    /** The specification's ceiling on a credential id. */
    private const MAX_CREDENTIAL_ID = 1023;

    private function __construct(
        /** The exact bytes, which are part of what was signed. */
        public string $raw,
        public string $rpIdHash,
        public int $flags,
        public int $signCount,
        public string $aaguid,
        public string $credentialId,
        public ?CoseKey $publicKey,
    ) {}

    public static function parse(string $bytes): self
    {
        if (\strlen($bytes) < 37) {
            throw WebAuthnException::malformed(
                'Authenticator data must be at least 37 bytes; got ' . \strlen($bytes) . '.',
            );
        }

        $rpIdHash = substr($bytes, 0, 32);
        $flags    = \ord($bytes[32]);

        /** @var array{1: int} $counter */
        $counter   = unpack('N', substr($bytes, 33, 4));
        $signCount = $counter[1];

        $offset       = 37;
        $aaguid       = '';
        $credentialId = '';
        $publicKey    = null;

        if (($flags & self::FLAG_ATTESTED_CREDENTIAL) !== 0) {
            if (\strlen($bytes) < $offset + 18) {
                throw WebAuthnException::malformed('Authenticator data is truncated inside its credential data.');
            }

            $aaguid = substr($bytes, $offset, 16);
            $offset += 16;

            /** @var array{1: int} $lengthBytes */
            $lengthBytes  = unpack('n', substr($bytes, $offset, 2));
            $idLength     = $lengthBytes[1];
            $offset      += 2;

            if ($idLength === 0 || $idLength > self::MAX_CREDENTIAL_ID) {
                throw WebAuthnException::malformed(
                    "A credential id of {$idLength} bytes is outside the permitted range.",
                );
            }

            if (\strlen($bytes) < $offset + $idLength) {
                throw WebAuthnException::malformed('Authenticator data is truncated inside its credential id.');
            }

            $credentialId = substr($bytes, $offset, $idLength);
            $offset      += $idLength;

            // The key has no length prefix, so parsing it is the only way to
            // find out where it stops.
            [$publicKey, $offset] = CoseKey::parse($bytes, $offset);
        }

        if (($flags & self::FLAG_EXTENSION_DATA) !== 0) {
            // Parsed and discarded. No extension here changes a verification
            // decision, and decoding it anyway means a malformed extension map
            // is caught as malformed input rather than silently ignored — which
            // is also what keeps the trailing-bytes check below honest.
            $decoder = new \Plugins\Passkeys\Domain\Cbor\CborDecoder(substr($bytes, $offset));
            $decoder->next();
            $offset += $decoder->position();
        }

        if ($offset !== \strlen($bytes)) {
            throw WebAuthnException::malformed(
                'Authenticator data has ' . (\strlen($bytes) - $offset) . ' unexpected trailing bytes.',
            );
        }

        return new self(
            raw: $bytes,
            rpIdHash: $rpIdHash,
            flags: $flags,
            signCount: $signCount,
            aaguid: $aaguid,
            credentialId: $credentialId,
            publicKey: $publicKey,
        );
    }

    public function has(int $flag): bool
    {
        return ($this->flags & $flag) !== 0;
    }

    public function userPresent(): bool
    {
        return $this->has(self::FLAG_USER_PRESENT);
    }

    public function userVerified(): bool
    {
        return $this->has(self::FLAG_USER_VERIFIED);
    }

    /**
     * Whether this credential can be synced to another device.
     *
     * The flag that distinguishes a passkey from a single-device security key,
     * and worth recording: a credential that is NOT backup-eligible is lost
     * with the device, so an application showing a user their keys should say
     * so — and should not let them delete their last synced credential while
     * keeping only hardware-bound ones.
     */
    public function backupEligible(): bool
    {
        return $this->has(self::FLAG_BACKUP_ELIGIBLE);
    }

    public function backedUp(): bool
    {
        return $this->has(self::FLAG_BACKED_UP);
    }

    public function aaguidHex(): string
    {
        return $this->aaguid === '' ? '' : bin2hex($this->aaguid);
    }

    /** Whether this data was signed for $rpId. */
    public function matchesRelyingParty(string $rpId): bool
    {
        return hash_equals(hash('sha256', $rpId, true), $this->rpIdHash);
    }
}
