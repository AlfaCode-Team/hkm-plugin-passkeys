<?php

declare(strict_types=1);

namespace Plugins\Passkeys\API\Contracts;

use Plugins\Passkeys\Domain\RegistrationResult;
use Plugins\Passkeys\Domain\StoredCredential;

/**
 * Where credentials live.
 *
 * Published so a deployment whose users are not in this plugin's table — an
 * existing credential store, a central identity service, a read-replica
 * arrangement — can supply its own without forking the ceremonies.
 *
 * TWO INVARIANTS AN IMPLEMENTATION MUST HOLD
 * ------------------------------------------
 * **A credential id is globally unique, not per-user.** The lookup in an
 * authentication has no user to scope by — that is the whole point of a
 * usernameless sign-in — so `findByCredentialId` must find the one credential
 * with that id or none. Scoping the column's uniqueness per user would let two
 * accounts hold the same id and make the lookup ambiguous at exactly the moment
 * it decides who is signing in.
 *
 * **`recordUse` must actually persist.** The clone check compares each
 * assertion's counter against the stored one, so an implementation that drops
 * the write has silently disabled it — while every sign-in keeps working, which
 * is why nobody would notice.
 */
interface PasskeyStoreContract
{
    /**
     * The one credential with this id, or null.
     *
     * @param string $credentialId base64url, as the browser sent it
     */
    public function findByCredentialId(string $credentialId): ?StoredCredential;

    /** @return list<StoredCredential> */
    public function allForUser(string $userId): array;

    public function save(string $userId, RegistrationResult $result, string $label): StoredCredential;

    /** Persist the new counter and the sign-in time. See the invariant above. */
    public function recordUse(string $credentialId, int $signCount, \DateTimeImmutable $at): void;

    /**
     * Remove one credential, scoped to its owner.
     *
     * The `$userId` argument is not redundant: without it an authenticated user
     * could delete another account's credential by id, and a credential id is a
     * value the client supplies.
     */
    public function delete(string $userId, string $credentialId): bool;
}
