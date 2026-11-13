<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

/**
 * A verified registration: everything that must be stored, and nothing that
 * must not.
 *
 * `publicKeyDer` is the DER rather than the COSE map the authenticator sent,
 * because the COSE parser's job is to handle hostile input ONCE, at
 * registration. Storing the COSE and re-parsing it on every sign-in would put
 * that parser back in the authentication path for the life of the credential.
 *
 * `backupEligible` is worth keeping even though nothing verifies against it: it
 * is what distinguishes a passkey that syncs from a credential bound to one
 * piece of hardware, so an application listing a user's keys can warn before
 * they delete the only one that would survive losing the device.
 */
final readonly class RegistrationResult
{
    public function __construct(
        /** base64url — the public identifier a later assertion arrives with. */
        public string $credentialId,
        public string $publicKeyDer,
        public CoseAlgorithm $algorithm,
        /** Raw Ed25519 key, or '' for the OpenSSL-verified algorithms. */
        public string $ed25519PublicKey,
        public int $signCount,
        /** Hex, or '' when the authenticator declined to identify its model. */
        public string $aaguid,
        public bool $userVerified,
        public bool $backupEligible,
        public bool $backedUp,
        public string $attestationFormat,
    ) {}
}
