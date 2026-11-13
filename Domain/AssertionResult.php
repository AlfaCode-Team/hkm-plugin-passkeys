<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

/**
 * A verified authentication.
 *
 * THERE IS DELIBERATELY NO `credentialId` HERE
 * --------------------------------------------
 * Authenticator data carries a credential id only when the attested-credential
 * flag is set, which happens during REGISTRATION and never during an assertion.
 * An assertion's id lives in the outer credential wrapper (`credential.id`),
 * which the caller has already used to look the stored key up — so it is
 * something the caller knows and this object cannot learn.
 *
 * An earlier version of this class had the field, populated from authenticator
 * data, and it was always the empty string. That is the worst shape for a bug
 * of this kind: a field named `credentialId` holding `''` reads as "this
 * credential has no id" rather than as "this code looked in the wrong place",
 * and a caller logging it or comparing it would have found nothing wrong until
 * the day it mattered. It is absent now so the question cannot be asked of the
 * wrong object.
 *
 * `signCount` is here so the caller can store it back. That write is not
 * optional: the clone check compares each assertion against the previous
 * counter, so a caller that verifies and forgets to persist the new value has
 * silently disabled the check — while every ceremony keeps succeeding, which is
 * why it would never be noticed.
 *
 * `userHandle` is the user id the AUTHENTICATOR believes this credential
 * belongs to, which is what makes a usernameless sign-in possible. It is a
 * claim from the client and must be treated as one: use it to LOOK UP the
 * credential, never as proof of who is signing in. Authority comes from the
 * credential record the server stored.
 */
final readonly class AssertionResult
{
    public function __construct(
        public int $signCount,
        public bool $userVerified,
        public bool $backedUp,
        /** Decoded; '' when the authenticator sent none. A hint, never authority. */
        public string $userHandle,
    ) {}
}
