<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\ClockPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\Passkeys\API\Contracts\PasskeyServiceContract;
use Plugins\Passkeys\API\Contracts\PasskeyStoreContract;
use Plugins\Passkeys\Domain\AttestationPolicy;
use Plugins\Passkeys\Domain\Base64Url;
use Plugins\Passkeys\Domain\Ceremony;
use Plugins\Passkeys\Domain\CoseAlgorithm;
use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;
use Plugins\Passkeys\Domain\RelyingParty;
use Plugins\Passkeys\Domain\StoredCredential;

/**
 * The ceremonies, joined to a challenge store and a credential store.
 *
 * {@see Ceremony} holds the cryptography and knows nothing about where
 * credentials live; this class holds the ORDERING, which is where the remaining
 * mistakes are available. Two of them are worth naming up front because both
 * look like harmless refactors:
 *
 * **The challenge is consumed before anything else can fail.** If the
 * credential were looked up first, an unknown id would return an error with the
 * challenge still in the session — so an attacker could probe ids one at a time
 * against a single challenge. Spending it first makes every attempt cost a
 * round trip for a new one.
 *
 * **A failure is logged with its reason and returned without one.** The public
 * message is identical for a wrong challenge, a foreign relying party and a bad
 * signature, because the differences are facts about whether a credential
 * exists and who owns it.
 */
final class PasskeyService implements PasskeyServiceContract
{
    public function __construct(
        private readonly PasskeyStoreContract $store,
        private readonly ChallengeStore $challenges,
        private readonly RelyingParty $relyingParty,
        private readonly ClockPort $clock,
        private readonly AttestationPolicy $attestation = AttestationPolicy::Ignore,
        /**
         * Whether a PIN, fingerprint or face is required.
         *
         * `false` by default, which asks for `preferred` rather than
         * `required`. A deployment using passkeys as the SOLE factor should set
         * this: without it, a security key with no PIN set satisfies a sign-in
         * on possession alone, which is a single factor whatever it feels like.
         */
        private readonly bool $requireUserVerification = false,
        /**
         * Cap per user.
         *
         * Not an arbitrary limit. `excludeCredentials` is sent to the browser
         * on every registration, and an unbounded list makes that payload grow
         * until the authenticator refuses it — so the cap is what keeps
         * registration working rather than a policy about tidiness.
         */
        private readonly int $maxPerUser = 20,
        private readonly ?LoggerPort $logger = null,
    ) {}

    public function registrationOptions(string $userId, string $userName, string $displayName): array
    {
        if ($userId === '') {
            throw WebAuthnException::rejected('A registration needs a user id.');
        }

        $existing = $this->store->allForUser($userId);

        return [
            'challenge' => $this->challenges->issue(ChallengeStore::PURPOSE_REGISTER),
            'rp'        => [
                'id'   => $this->relyingParty->id,
                'name' => $this->relyingParty->name,
            ],
            'user' => [
                // The user handle. base64url because it is `bytes` in the
                // specification, and the authenticator stores it verbatim —
                // which is why it must be an opaque id and never an email
                // address: it is written to the authenticator and syncs to the
                // user's other devices, where it may be visible.
                'id'          => Base64Url::encode($userId),
                'name'        => $userName,
                'displayName' => $displayName !== '' ? $displayName : $userName,
            ],
            'pubKeyCredParams' => array_map(
                static fn (CoseAlgorithm $algorithm): array => [
                    'type' => 'public-key',
                    'alg'  => $algorithm->value,
                ],
                CoseAlgorithm::preferred(),
            ),
            // So an authenticator that already holds a credential for this user
            // declines rather than silently creating a second one, which would
            // leave the user with two keys on one device and no way to tell
            // them apart.
            'excludeCredentials' => array_map(
                static fn (StoredCredential $credential): array => [
                    'type' => 'public-key',
                    'id'   => $credential->credentialId,
                ],
                $existing,
            ),
            'authenticatorSelection' => [
                // `required` asks for a DISCOVERABLE credential — one the
                // authenticator can offer without being told the user's id,
                // which is what a usernameless sign-in needs.
                'residentKey'      => 'required',
                'requireResidentKey' => true,
                'userVerification' => $this->requireUserVerification ? 'required' : 'preferred',
            ],
            'attestation' => $this->attestation->conveyancePreference(),
            'timeout'     => 120_000,
        ];
    }

    public function completeRegistration(string $userId, array $credential, string $label = ''): StoredCredential
    {
        $challenge = $this->challenges->consume(ChallengeStore::PURPOSE_REGISTER);

        try {
            $result = Ceremony::verifyRegistration(
                self::response($credential),
                $challenge,
                $this->relyingParty,
                $this->attestation,
                $this->requireUserVerification,
            );
        } catch (WebAuthnException $e) {
            $this->complain('passkeys.registration.refused', $e, ['userId' => $userId]);

            throw $e;
        }

        // A credential id already in the table is either a replay of a previous
        // registration or a collision. Either way it must not overwrite the
        // existing row, because that row may belong to a different account —
        // and silently rebinding a credential to a new user is an account
        // takeover with no attacker required beyond a replayed request.
        if ($this->store->findByCredentialId($result->credentialId) !== null) {
            $refusal = WebAuthnException::rejected('That credential is already registered.');
            $this->complain('passkeys.registration.duplicate', $refusal, ['userId' => $userId]);

            throw $refusal;
        }

        if (\count($this->store->allForUser($userId)) >= $this->maxPerUser) {
            throw WebAuthnException::rejected(
                "This account already has {$this->maxPerUser} passkeys. Remove one before adding another.",
            );
        }

        $stored = $this->store->save($userId, $result, $label !== '' ? $label : 'Passkey');

        $this->logger?->info('passkeys.registered', [
            'userId'      => $userId,
            'algorithm'   => $result->algorithm->label(),
            'deviceBound' => !$result->backupEligible,
            'attestation' => $result->attestationFormat,
        ]);

        return $stored;
    }

    public function authenticationOptions(string $userId = ''): array
    {
        $options = [
            'challenge'        => $this->challenges->issue(ChallengeStore::PURPOSE_LOGIN),
            'rpId'             => $this->relyingParty->id,
            'userVerification' => $this->requireUserVerification ? 'required' : 'preferred',
            'timeout'          => 120_000,
        ];

        if ($userId === '') {
            // No allowCredentials at all: a discoverable request. Deliberately
            // not an empty array in the payload either — some authenticators
            // treat `allowCredentials: []` as "none are acceptable".
            return $options;
        }

        $options['allowCredentials'] = array_map(
            static fn (StoredCredential $credential): array => [
                'type' => 'public-key',
                'id'   => $credential->credentialId,
            ],
            $this->store->allForUser($userId),
        );

        return $options;
    }

    public function completeAuthentication(array $credential): StoredCredential
    {
        // First, so that every attempt spends it. See the class docblock.
        $challenge = $this->challenges->consume(ChallengeStore::PURPOSE_LOGIN);

        $credentialId = $credential['id'] ?? $credential['rawId'] ?? null;

        if (!\is_string($credentialId) || $credentialId === '') {
            throw WebAuthnException::malformed('The credential has no id.');
        }

        // Validated as base64url before it reaches the store, so a storage
        // implementation never sees a value this plugin has not checked.
        Base64Url::decode($credentialId, 'credential id');

        $stored = $this->store->findByCredentialId($credentialId);

        if ($stored === null) {
            $refusal = WebAuthnException::rejected("No credential is registered with id [{$credentialId}].");
            $this->complain('passkeys.authentication.unknown_credential', $refusal, []);

            // The same generic message as every other failure: "unknown
            // credential" and "bad signature" are different facts about whether
            // a credential exists, and the second is only reachable by someone
            // who already knows a real id.
            throw $refusal;
        }

        try {
            $result = Ceremony::verifyAssertion(
                self::response($credential),
                $challenge,
                $this->relyingParty,
                $stored->key(),
                $stored->signCount,
                $this->requireUserVerification,
            );
        } catch (WebAuthnException $e) {
            $this->complain('passkeys.authentication.refused', $e, ['userId' => $stored->userId]);

            throw $e;
        }

        // The authenticator's own view of who this credential belongs to. A
        // mismatch means the client is presenting a credential as belonging to
        // a different account than the server recorded — which the server's
        // record settles, but which is worth refusing rather than ignoring:
        // there is no benign way for the two to disagree.
        if ($result->userHandle !== '' && !hash_equals($stored->userId, $result->userHandle)) {
            $refusal = WebAuthnException::rejected(
                'The authenticator reports a different user for this credential than the server recorded.',
            );
            $this->complain('passkeys.authentication.user_handle_mismatch', $refusal, [
                'userId' => $stored->userId,
            ]);

            throw $refusal;
        }

        $this->store->recordUse($stored->credentialId, $result->signCount, $this->clock->now());

        $this->logger?->info('passkeys.authenticated', [
            'userId'       => $stored->userId,
            'userVerified' => $result->userVerified,
        ]);

        return $stored;
    }

    public function credentialsFor(string $userId): array
    {
        return $userId === '' ? [] : $this->store->allForUser($userId);
    }

    public function forget(string $userId, string $credentialId): bool
    {
        if ($userId === '' || $credentialId === '') {
            return false;
        }

        $removed = $this->store->delete($userId, $credentialId);

        if ($removed) {
            $this->logger?->info('passkeys.forgotten', ['userId' => $userId]);
        }

        return $removed;
    }

    /**
     * @param  array<string, mixed>  $credential
     * @return array<string, mixed>
     */
    private static function response(array $credential): array
    {
        $response = $credential['response'] ?? null;

        if (!\is_array($response)) {
            throw WebAuthnException::malformed('The credential has no `response` object.');
        }

        /** @var array<string, mixed> $response */
        return $response;
    }

    /** @param array<string, mixed> $context */
    private function complain(string $event, WebAuthnException $e, array $context): void
    {
        // The REASON goes in the log; the message goes to the client. This is
        // the only place the detail is recorded, so an operator investigating a
        // failed sign-in has something to read.
        $this->logger?->warning($event, $context + [
            'kind'   => $e->kind,
            'reason' => $e->reason,
        ]);
    }
}
