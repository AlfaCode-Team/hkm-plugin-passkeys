<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

use Plugins\Passkeys\Domain\Cbor\CborDecoder;
use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;

/**
 * The two WebAuthn ceremonies, verified. No storage, no HTTP, no clock.
 *
 * This is the part a vendor library would have supplied, and it is written here
 * for one reason: the checks ARE the security, so they should be readable in
 * the repository that depends on them. Everything else in this plugin —
 * options, persistence, routes — is plumbing around the two methods below.
 *
 * WHAT IS ACTUALLY BEING PROVEN
 * -----------------------------
 * Not "this is a YubiKey". The claim a successful ceremony supports is:
 *
 *   someone, in possession of the private key for this credential id, signed a
 *   challenge THIS server issued moments ago, naming THIS relying party, from
 *   an origin we permit.
 *
 * Each clause corresponds to a check, and dropping any one collapses the claim:
 *
 * | Dropped | What becomes possible |
 * |---|---|
 * | signature | anyone who knows a credential id signs in as its owner |
 * | challenge | a captured response replays forever |
 * | rpIdHash | a credential from another site is accepted here |
 * | origin | a page the application does not control runs the ceremony |
 * | type | a registration response is replayed as an authentication |
 * | user presence | a credential is used with nobody at the keyboard |
 *
 * None of them is optional and none is defensive programming. They are the
 * protocol.
 */
final class Ceremony
{
    /**
     * Verify a registration response and extract the credential to store.
     *
     * @param array<string, mixed> $response the `response` member of the credential
     */
    public static function verifyRegistration(
        array $response,
        string $expectedChallenge,
        RelyingParty $relyingParty,
        AttestationPolicy $policy = AttestationPolicy::Ignore,
        bool $requireUserVerification = false,
    ): RegistrationResult {
        $clientDataJson = Base64Url::decode(
            self::field($response, 'clientDataJSON'),
            'clientDataJSON',
        );

        $clientData = ClientData::parse($clientDataJson);
        $clientData->assertValid(ClientData::TYPE_CREATE, $expectedChallenge, $relyingParty->origins);

        $attestation = CborDecoder::decodeAll(
            Base64Url::decode(self::field($response, 'attestationObject'), 'attestationObject'),
            'attestation object',
        );

        if (!\is_array($attestation)) {
            throw WebAuthnException::malformed('The attestation object is not a CBOR map.');
        }

        $format   = $attestation['fmt'] ?? null;
        $authData = $attestation['authData'] ?? null;

        if (!\is_string($format) || !\is_string($authData)) {
            throw WebAuthnException::malformed('The attestation object has no `fmt` and `authData`.');
        }

        $authenticator = AuthenticatorData::parse($authData);

        self::assertAuthenticatorData($authenticator, $relyingParty, $requireUserVerification);

        // AT must be set on a registration: without attested credential data
        // there is no public key, and a response without one is an
        // authentication response wearing the wrong type.
        if (!$authenticator->has(AuthenticatorData::FLAG_ATTESTED_CREDENTIAL)) {
            throw WebAuthnException::rejected('The registration carries no attested credential data.');
        }

        $publicKey = $authenticator->publicKey;

        if ($publicKey === null) {
            throw WebAuthnException::malformed('The registration carries no credential public key.');
        }

        if ($policy === AttestationPolicy::SelfAttested) {
            self::assertSelfAttestation(
                $format,
                $attestation['attStmt'] ?? null,
                $authenticator,
                $clientData,
                $publicKey,
            );
        }

        return new RegistrationResult(
            credentialId: Base64Url::encode($authenticator->credentialId),
            publicKeyDer: $publicKey->der,
            algorithm: $publicKey->algorithm,
            ed25519PublicKey: $publicKey->ed25519,
            signCount: $authenticator->signCount,
            aaguid: $authenticator->aaguidHex(),
            userVerified: $authenticator->userVerified(),
            backupEligible: $authenticator->backupEligible(),
            backedUp: $authenticator->backedUp(),
            attestationFormat: $format,
        );
    }

    /**
     * Verify an authentication response against a stored credential.
     *
     * @param array<string, mixed> $response
     */
    public static function verifyAssertion(
        array $response,
        string $expectedChallenge,
        RelyingParty $relyingParty,
        CoseKey $storedKey,
        int $storedSignCount,
        bool $requireUserVerification = false,
    ): AssertionResult {
        $clientData = ClientData::parse(
            Base64Url::decode(self::field($response, 'clientDataJSON'), 'clientDataJSON'),
        );

        $clientData->assertValid(ClientData::TYPE_GET, $expectedChallenge, $relyingParty->origins);

        $authenticator = AuthenticatorData::parse(
            Base64Url::decode(self::field($response, 'authenticatorData'), 'authenticatorData'),
        );

        self::assertAuthenticatorData($authenticator, $relyingParty, $requireUserVerification);

        $signature = Base64Url::decode(self::field($response, 'signature'), 'signature');

        // The signed message: authenticator data, then the hash of the client
        // data. Concatenated in that order and nothing else — no length
        // prefixes, no separator. Getting the order wrong produces a
        // verification that fails for every credential, which at least fails
        // closed.
        $signedData = $authenticator->raw . $clientData->hash();

        if (!$storedKey->verify($signedData, $signature)) {
            throw WebAuthnException::rejected(
                'The signature does not verify against the stored credential key.',
            );
        }

        self::assertSignCount($authenticator->signCount, $storedSignCount);

        $userHandle = $response['userHandle'] ?? null;

        // No credential id: an assertion's authenticator data does not contain
        // one. See AssertionResult.
        return new AssertionResult(
            signCount: $authenticator->signCount,
            userVerified: $authenticator->userVerified(),
            backedUp: $authenticator->backedUp(),
            userHandle: \is_string($userHandle) && $userHandle !== ''
                ? Base64Url::decode($userHandle, 'userHandle')
                : '',
        );
    }

    /** The checks both ceremonies share. */
    private static function assertAuthenticatorData(
        AuthenticatorData $data,
        RelyingParty $relyingParty,
        bool $requireUserVerification,
    ): void {
        if (!$data->matchesRelyingParty($relyingParty->id)) {
            throw WebAuthnException::rejected(
                "The credential was created for a different relying party than [{$relyingParty->id}].",
            );
        }

        // User presence means a human did something — a touch, a tap. Its
        // absence means the authenticator acted on its own, which is a mode
        // that exists (silent authentication) and must never satisfy a sign-in.
        if (!$data->userPresent()) {
            throw WebAuthnException::rejected('The user-presence flag is not set.');
        }

        // User VERIFICATION is the stronger claim: a PIN, a fingerprint, a face.
        // Required only when asked for, because requiring it unconditionally
        // turns away security keys with no PIN set — and because a deployment
        // using passkeys as a second factor wants presence, not verification.
        if ($requireUserVerification && !$data->userVerified()) {
            throw WebAuthnException::rejected(
                'User verification was required but the authenticator did not perform it.',
            );
        }
    }

    /**
     * The clone check.
     *
     * An authenticator's counter increases with every assertion, so a value
     * that did not advance means two copies of the same private key are in use
     * — the signal that a hardware key has been extracted and duplicated.
     *
     * BOTH ZERO MEANS NO COUNTER, NOT A REPLAY, and this is the branch that
     * matters for passkeys. A credential that syncs across devices cannot keep
     * a coherent counter, so iCloud Keychain and Google Password Manager report
     * 0 forever. Treating that as a clone would reject every passkey on every
     * sign-in, which is why the check is skipped rather than failed when the
     * authenticator declines to count.
     */
    private static function assertSignCount(int $received, int $stored): void
    {
        if ($received === 0 && $stored === 0) {
            return;
        }

        if ($received <= $stored) {
            throw WebAuthnException::rejected(
                "The signature counter did not advance ({$received} after {$stored}); "
                . 'the credential may have been cloned.',
            );
        }
    }

    /**
     * `packed` self-attestation: the authenticator signed the registration with
     * the key being registered.
     *
     * Only `none` and self-attested `packed` are understood. An `x5c` chain is
     * REFUSED rather than ignored under this policy, because ignoring it would
     * mean reporting a successful attestation check on a certificate nothing
     * validated — and an attacker can generate as many of those as they like.
     *
     * @param mixed $statement the `attStmt` member
     */
    private static function assertSelfAttestation(
        string $format,
        mixed $statement,
        AuthenticatorData $authenticator,
        ClientData $clientData,
        CoseKey $publicKey,
    ): void {
        if ($format === 'none') {
            throw WebAuthnException::rejected(
                'The authenticator provided no attestation, and this deployment requires '
                . 'self-attestation (PASSKEYS_ATTESTATION=self).',
            );
        }

        if ($format !== 'packed') {
            throw WebAuthnException::unsupported(
                "Attestation format [{$format}] is not supported. Only `packed` self-attestation is verified; "
                . 'set PASSKEYS_ATTESTATION=none to accept the credential without checking attestation.',
            );
        }

        if (!\is_array($statement)) {
            throw WebAuthnException::malformed('The packed attestation statement is missing.');
        }

        if (isset($statement['x5c'])) {
            throw WebAuthnException::unsupported(
                'This credential carries a certificate chain, which would need the FIDO Metadata Service '
                . 'to validate. Set PASSKEYS_ATTESTATION=none to accept it without attestation.',
            );
        }

        $signature = $statement['sig'] ?? null;
        $algorithm = $statement['alg'] ?? null;

        if (!\is_string($signature) || !\is_int($algorithm)) {
            throw WebAuthnException::malformed('The packed attestation statement has no `sig` and `alg`.');
        }

        if ($algorithm !== $publicKey->algorithm->value) {
            throw WebAuthnException::rejected(
                'The attestation algorithm does not match the credential key algorithm.',
            );
        }

        if (!$publicKey->verify($authenticator->raw . $clientData->hash(), $signature)) {
            throw WebAuthnException::rejected('The self-attestation signature does not verify.');
        }
    }

    /** @param array<string, mixed> $response */
    private static function field(array $response, string $name): string
    {
        $value = $response[$name] ?? null;

        if (!\is_string($value) || $value === '') {
            throw WebAuthnException::malformed("The credential response has no `{$name}`.");
        }

        return $value;
    }
}
