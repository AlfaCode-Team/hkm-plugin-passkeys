<?php

declare(strict_types=1);

namespace Plugins\Passkeys\API\Contracts;

use Plugins\Passkeys\Domain\StoredCredential;

/**
 * The four operations a passkey flow needs, plus key management.
 *
 * `completeAuthentication()` RETURNS A CREDENTIAL AND DOES NOT SIGN ANYONE IN,
 * which is the one shape decision in this contract worth explaining.
 *
 * Establishing a session is the Auth plugin's job and the ways to do it are not
 * interchangeable: a web app wants `AuthServiceContract::startSession()` with
 * the session rotated, an API wants `tokensFor()`, and a step-up flow wants
 * neither because the user is already signed in and is only proving presence.
 * A method here that picked one would be wrong for the other two and would make
 * this plugin depend on a specific answer.
 *
 * So this verifies, records the counter, and hands back the credential. What
 * that means for the session is the caller's decision, and the shipped
 * controller shows one way of making it.
 */
interface PasskeyServiceContract
{
    /**
     * Options for `navigator.credentials.create()`, with a fresh challenge
     * bound to this session.
     *
     * @return array<string, mixed> JSON-serialisable, base64url where binary
     */
    public function registrationOptions(string $userId, string $userName, string $displayName): array;

    /**
     * Verify a registration and store the credential.
     *
     * @param array<string, mixed> $credential the whole PublicKeyCredential object
     * @throws \Plugins\Passkeys\Domain\Exceptions\WebAuthnException on any failure
     */
    public function completeRegistration(string $userId, array $credential, string $label = ''): StoredCredential;

    /**
     * Options for `navigator.credentials.get()`.
     *
     * An empty `$userId` produces a DISCOVERABLE request — no
     * `allowCredentials`, so the authenticator offers whatever it holds for
     * this site. That is what makes a passkey sign-in possible with no username
     * typed, and it is the reason credential ids must be unique globally rather
     * than per user.
     *
     * @return array<string, mixed>
     */
    public function authenticationOptions(string $userId = ''): array;

    /**
     * Verify an assertion and return the credential that made it.
     *
     * The caller establishes the session. See the class docblock.
     *
     * @param array<string, mixed> $credential
     * @throws \Plugins\Passkeys\Domain\Exceptions\WebAuthnException on any failure
     */
    public function completeAuthentication(array $credential): StoredCredential;

    /** @return list<StoredCredential> */
    public function credentialsFor(string $userId): array;

    /** Remove one of this user's credentials. False when they do not own it. */
    public function forget(string $userId, string $credentialId): bool;
}
