<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

/**
 * How much to believe about WHICH authenticator produced a credential.
 *
 * WHY `Ignore` IS THE DEFAULT, AND WHY THAT IS NOT LAZINESS
 * ---------------------------------------------------------
 * Attestation answers a question most applications are not asking: "is this
 * really a YubiKey 5, model such-and-such". Answering it properly needs the
 * FIDO Metadata Service — a signed, regularly-rotated blob of root
 * certificates — plus certificate-chain validation, plus a policy about what to
 * do when a vendor's root expires. That is a subsystem, not a check.
 *
 * And for passkeys it mostly cannot be answered anyway. iCloud Keychain, Google
 * Password Manager and Windows Hello return `none` or self-attestation by
 * design, because a syncing credential is not bound to one piece of hardware
 * and attesting to a device would be a lie. The W3C's own guidance is that a
 * relying party with no hardware-allowlist requirement should request
 * `attestation: "none"`.
 *
 * What makes the credential trustworthy is not attestation. It is that the
 * authenticator proved possession of the private key, over a challenge this
 * server issued, for this relying party id — all of which is verified
 * regardless of this setting.
 *
 * `SelfAttested` is for a deployment that wants the extra proof available
 * without the metadata service: the authenticator signs the registration with
 * the very key being registered, which demonstrates possession at creation time
 * too. It rejects `none`, so it will turn away some platform authenticators —
 * which is the trade, stated so an operator can make it deliberately.
 *
 * FULL attestation is deliberately absent rather than half-built. A chain
 * validated against no trusted roots is not a weaker check than this one; it is
 * a check that reports success for any self-signed certificate an attacker
 * cares to generate.
 */
enum AttestationPolicy: string
{
    case Ignore       = 'none';
    case SelfAttested = 'self';

    public static function fromName(string $value): self
    {
        return self::tryFrom(strtolower(trim($value))) ?? self::Ignore;
    }

    /** What to put in `authenticatorSelection`/`attestation` for the browser. */
    public function conveyancePreference(): string
    {
        return $this === self::Ignore ? 'none' : 'direct';
    }
}
