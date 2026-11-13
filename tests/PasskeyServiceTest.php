<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Passkeys;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SessionPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SystemClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Passkeys\API\Contracts\PasskeyStoreContract;
use Plugins\Passkeys\Application\Services\ChallengeStore;
use Plugins\Passkeys\Application\Services\PasskeyService;
use Plugins\Passkeys\Domain\CoseAlgorithm;
use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;
use Plugins\Passkeys\Domain\RegistrationResult;
use Plugins\Passkeys\Domain\RelyingParty;
use Plugins\Passkeys\Domain\StoredCredential;

/**
 * The service layer — the ORDERING, which is where the remaining mistakes are.
 *
 * {@see \Plugins\Passkeys\Domain\Ceremony} holds the cryptography and is tested
 * separately. This file tests the decisions around it: when the challenge is
 * spent, what happens to a credential id that is already registered, and
 * whether the authenticator's claim about who owns a credential is allowed to
 * disagree with the server's record.
 *
 * All three look like harmless refactors if you do not know why they are the
 * way they are, which is exactly why they have tests.
 */
#[CoversClass(PasskeyService::class)]
#[CoversClass(ChallengeStore::class)]
final class PasskeyServiceTest extends TestCase
{
    public function test_registration_options_carry_a_challenge_and_the_relying_party(): void
    {
        $options = $this->service()->registrationOptions('user-1', 'ada', 'Ada Lovelace');

        self::assertSame('example.com', $options['rp']['id']);
        self::assertNotSame('', $options['challenge']);
        self::assertSame('Ada Lovelace', $options['user']['displayName']);

        // ES256 first: universally supported, 64-byte signatures, cheaper to
        // verify than RSA.
        self::assertSame(CoseAlgorithm::ES256->value, $options['pubKeyCredParams'][0]['alg']);

        // `required`, so the credential is discoverable and a usernameless
        // sign-in is possible at all.
        self::assertSame('required', $options['authenticatorSelection']['residentKey']);
    }

    /**
     * The user handle is written to the authenticator and syncs to the user's
     * other devices, where it may be visible — so it must be an opaque id and
     * never an email address.
     */
    public function test_the_user_handle_is_the_opaque_id_base64url_encoded(): void
    {
        $options = $this->service()->registrationOptions('user-1', 'ada@example.com', '');

        self::assertSame('dXNlci0x', $options['user']['id'], 'base64url of "user-1"');
        self::assertSame('ada@example.com', $options['user']['name'], 'the name is for display only');
    }

    public function test_a_registration_round_trips_into_the_store(): void
    {
        $store         = new ArrayPasskeyStore();
        $session       = new ArraySession();
        $service       = $this->service($store, $session);
        $authenticator = new FakeAuthenticator();

        $options = $service->registrationOptions('user-1', 'ada', 'Ada');

        $credential = $service->completeRegistration(
            'user-1',
            ['response' => $authenticator->register((string) $options['challenge'])],
            'MacBook',
        );

        self::assertSame('MacBook', $credential->label);
        self::assertSame('user-1', $credential->userId);
        self::assertNotNull($store->findByCredentialId($credential->credentialId));
    }

    /**
     * A challenge that survives its own use can be replayed for as long as the
     * session lives: capture one successful response and resubmit it whenever
     * you like.
     */
    public function test_a_challenge_can_only_be_used_once(): void
    {
        $service       = $this->service();
        $authenticator = new FakeAuthenticator();

        $challenge = (string) $service->registrationOptions('user-1', 'ada', '')['challenge'];
        $response  = ['response' => $authenticator->register($challenge)];

        $service->completeRegistration('user-2', $response, '');

        $this->assertRefused('already been used', fn () => $service->completeRegistration('user-3', $response, ''));
    }

    /**
     * The challenge is spent BEFORE the ceremony can fail, so a wrong response
     * costs a round trip for a new one.
     *
     * Without this, an attacker could probe credential ids one at a time
     * against a single challenge.
     */
    public function test_a_failed_attempt_still_spends_the_challenge(): void
    {
        $service = $this->service();

        $service->authenticationOptions();

        // A well-formed but unregistered credential id — the shape a probe
        // takes. (Not a malformed id: that is refused by base64url validation
        // before the lookup, which would prove something different.)
        $probe = ['id' => 'dW5rbm93bi1jcmVkZW50aWFs', 'response' => []];

        $this->assertRefused('No credential is registered', fn () => $service->completeAuthentication($probe));

        // The challenge is gone, so the SECOND probe cannot reuse it. Without
        // the consume-first ordering this attempt would reach the lookup again,
        // and an attacker could walk a list of ids against one challenge.
        $this->assertRefused('already been used', fn () => $service->completeAuthentication($probe));
    }

    public function test_an_expired_challenge_is_refused(): void
    {
        $session = new ArraySession();
        $service = $this->service(new ArrayPasskeyStore(), $session, challengeLifetime: 1);

        $challenge = (string) $service->registrationOptions('user-1', 'ada', '')['challenge'];

        // Rewind the stored expiry rather than sleeping: a test that waits is a
        // test nobody runs.
        $stored = $session->data['passkeys.challenge.create'];
        self::assertIsArray($stored);
        $stored['expires'] = time() - 1;
        $session->data['passkeys.challenge.create'] = $stored;

        $this->assertRefused('expired', fn () => $service->completeRegistration(
            'user-1',
            ['response' => (new FakeAuthenticator())->register($challenge)],
            '',
        ));
    }

    /**
     * Rebinding an existing credential id to a new user would be an account
     * takeover with no attacker required beyond a replayed request.
     */
    public function test_a_credential_id_already_registered_is_refused(): void
    {
        $store         = new ArrayPasskeyStore();
        $session       = new ArraySession();
        $service       = $this->service($store, $session);
        $authenticator = new FakeAuthenticator();

        $first = (string) $service->registrationOptions('user-1', 'ada', '')['challenge'];
        $service->completeRegistration('user-1', ['response' => $authenticator->register($first)], '');

        $second = (string) $service->registrationOptions('user-2', 'bob', '')['challenge'];

        $this->assertRefused('already registered', fn () => $service->completeRegistration(
            'user-2',
            ['response' => $authenticator->register($second)],
            '',
        ));

        self::assertSame('user-1', $store->findByCredentialId(
            \Plugins\Passkeys\Domain\Base64Url::encode($authenticator->credentialId),
        )?->userId, 'and the original owner is untouched');
    }

    /**
     * The cap is what keeps registration WORKING: `excludeCredentials` is sent
     * to the browser on every registration, and an unbounded list grows that
     * payload until the authenticator refuses it.
     */
    public function test_the_per_user_cap_is_enforced(): void
    {
        $store   = new ArrayPasskeyStore();
        $session = new ArraySession();
        $service = $this->service($store, $session, maxPerUser: 2);

        for ($i = 0; $i < 2; ++$i) {
            $challenge = (string) $service->registrationOptions('user-1', 'ada', '')['challenge'];
            $service->completeRegistration(
                'user-1',
                ['response' => (new FakeAuthenticator())->register($challenge)],
                '',
            );
        }

        $challenge = (string) $service->registrationOptions('user-1', 'ada', '')['challenge'];

        $this->assertRefused('already has 2 passkeys', fn () => $service->completeRegistration(
            'user-1',
            ['response' => (new FakeAuthenticator())->register($challenge)],
            '',
        ));
    }

    public function test_existing_credentials_are_excluded_from_a_new_registration(): void
    {
        $store         = new ArrayPasskeyStore();
        $session       = new ArraySession();
        $service       = $this->service($store, $session);
        $authenticator = new FakeAuthenticator();

        $challenge = (string) $service->registrationOptions('user-1', 'ada', '')['challenge'];
        $service->completeRegistration('user-1', ['response' => $authenticator->register($challenge)], '');

        $options = $service->registrationOptions('user-1', 'ada', '');

        self::assertCount(1, $options['excludeCredentials']);
        self::assertSame(
            \Plugins\Passkeys\Domain\Base64Url::encode($authenticator->credentialId),
            $options['excludeCredentials'][0]['id'],
        );
    }

    // ── Authentication ────────────────────────────────────────────────────────

    public function test_an_authentication_verifies_and_records_the_counter(): void
    {
        $store         = new ArrayPasskeyStore();
        $session       = new ArraySession();
        $service       = $this->service($store, $session);
        $authenticator = new FakeAuthenticator();

        $challenge = (string) $service->registrationOptions('user-1', 'ada', '')['challenge'];
        $service->completeRegistration('user-1', ['response' => $authenticator->register($challenge)], '');

        $loginChallenge = (string) $service->authenticationOptions()['challenge'];

        $credential = $service->completeAuthentication([
            'id'       => \Plugins\Passkeys\Domain\Base64Url::encode($authenticator->credentialId),
            'response' => $authenticator->authenticate($loginChallenge, signCount: 9),
        ]);

        self::assertSame('user-1', $credential->userId);

        // The write is not optional: the clone check compares each assertion
        // against the stored counter, so dropping it silently disables the
        // check while every sign-in keeps working.
        self::assertSame(9, $store->findByCredentialId($credential->credentialId)?->signCount);
        self::assertNotNull($store->findByCredentialId($credential->credentialId)?->lastUsedAt);
    }

    /**
     * Discoverable: no `allowCredentials` AT ALL, not an empty array — some
     * authenticators read `allowCredentials: []` as "none are acceptable".
     */
    public function test_authentication_options_are_discoverable_by_default(): void
    {
        $options = $this->service()->authenticationOptions();

        self::assertArrayNotHasKey('allowCredentials', $options);
        self::assertSame('example.com', $options['rpId']);
    }

    public function test_naming_a_user_narrows_the_options_to_their_credentials(): void
    {
        $store         = new ArrayPasskeyStore();
        $session       = new ArraySession();
        $service       = $this->service($store, $session);
        $authenticator = new FakeAuthenticator();

        $challenge = (string) $service->registrationOptions('user-1', 'ada', '')['challenge'];
        $service->completeRegistration('user-1', ['response' => $authenticator->register($challenge)], '');

        self::assertCount(1, $service->authenticationOptions('user-1')['allowCredentials']);
        self::assertSame([], $service->authenticationOptions('nobody')['allowCredentials']);
    }

    public function test_an_unknown_credential_is_refused(): void
    {
        $service = $this->service();
        $service->authenticationOptions();

        $this->assertRefused('No credential is registered', fn () => $service->completeAuthentication([
            'id'       => 'dW5rbm93bg',
            'response' => (new FakeAuthenticator())->authenticate('whatever'),
        ]));
    }

    /**
     * There is no benign way for the authenticator's view of the owner and the
     * server's record to disagree.
     */
    public function test_a_user_handle_naming_a_different_owner_is_refused(): void
    {
        $store         = new ArrayPasskeyStore();
        $session       = new ArraySession();
        $service       = $this->service($store, $session);
        $authenticator = new FakeAuthenticator();

        $challenge = (string) $service->registrationOptions('user-1', 'ada', '')['challenge'];
        $service->completeRegistration('user-1', ['response' => $authenticator->register($challenge)], '');

        $loginChallenge = (string) $service->authenticationOptions()['challenge'];

        $this->assertRefused('different user', fn () => $service->completeAuthentication([
            'id'       => \Plugins\Passkeys\Domain\Base64Url::encode($authenticator->credentialId),
            'response' => $authenticator->authenticate($loginChallenge, userHandle: 'user-9'),
        ]));
    }

    public function test_a_credential_id_that_is_not_base64url_is_refused_before_the_store_sees_it(): void
    {
        $store   = new ArrayPasskeyStore();
        $session = new ArraySession();
        $service = $this->service($store, $session);

        $service->authenticationOptions();

        $this->assertRefused('not base64url', fn () => $service->completeAuthentication([
            'id'       => '!!! not base64url !!!',
            'response' => (new FakeAuthenticator())->authenticate('x'),
        ]));

        self::assertSame([], $store->lookups, 'a storage implementation never sees an unchecked value');
    }

    // ── Management ────────────────────────────────────────────────────────────

    public function test_forgetting_is_scoped_to_the_owner(): void
    {
        $store         = new ArrayPasskeyStore();
        $session       = new ArraySession();
        $service       = $this->service($store, $session);
        $authenticator = new FakeAuthenticator();

        $challenge = (string) $service->registrationOptions('user-1', 'ada', '')['challenge'];
        $stored    = $service->completeRegistration(
            'user-1',
            ['response' => $authenticator->register($challenge)],
            '',
        );

        // Another signed-in user supplying someone else's credential id.
        self::assertFalse($service->forget('user-2', $stored->credentialId));
        self::assertNotNull($store->findByCredentialId($stored->credentialId));

        self::assertTrue($service->forget('user-1', $stored->credentialId));
        self::assertNull($store->findByCredentialId($stored->credentialId));
    }

    public function test_a_registration_with_no_user_is_refused(): void
    {
        $this->assertRefused('needs a user id', fn () => $this->service()->registrationOptions('', 'ada', ''));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function service(
        ?ArrayPasskeyStore $store = null,
        ?ArraySession $session = null,
        int $maxPerUser = 20,
        int $challengeLifetime = 120,
    ): PasskeyService {
        return new PasskeyService(
            store: $store ?? new ArrayPasskeyStore(),
            challenges: new ChallengeStore($session ?? new ArraySession(), $challengeLifetime),
            relyingParty: new RelyingParty('example.com', 'Example', ['https://app.example.com']),
            clock: new SystemClock(),
            maxPerUser: $maxPerUser,
        );
    }

    private function assertRefused(string $reasonFragment, \Closure $work): void
    {
        try {
            $work();
        } catch (WebAuthnException $e) {
            self::assertStringContainsString(
                $reasonFragment,
                $e->reason,
                "refused, but for the wrong reason: {$e->reason}",
            );

            return;
        }

        self::fail("accepted; expected a refusal mentioning [{$reasonFragment}]");
    }
}

/** @internal */
final class ArrayPasskeyStore implements PasskeyStoreContract
{
    /** @var array<string, StoredCredential> */
    public array $credentials = [];

    /** Every id this store was asked about, so a test can prove it was not. */
    /** @var list<string> */
    public array $lookups = [];

    public function findByCredentialId(string $credentialId): ?StoredCredential
    {
        $this->lookups[] = $credentialId;

        return $this->credentials[$credentialId] ?? null;
    }

    public function allForUser(string $userId): array
    {
        return array_values(array_filter(
            $this->credentials,
            static fn (StoredCredential $credential): bool => $credential->userId === $userId,
        ));
    }

    public function save(string $userId, RegistrationResult $result, string $label): StoredCredential
    {
        $credential = new StoredCredential(
            credentialId: $result->credentialId,
            userId: $userId,
            algorithm: $result->algorithm,
            publicKeyDer: $result->publicKeyDer,
            ed25519PublicKey: $result->ed25519PublicKey,
            signCount: $result->signCount,
            label: $label,
            aaguid: $result->aaguid,
            backupEligible: $result->backupEligible,
            createdAt: new \DateTimeImmutable(),
        );

        $this->credentials[$result->credentialId] = $credential;

        return $credential;
    }

    public function recordUse(string $credentialId, int $signCount, \DateTimeImmutable $at): void
    {
        $existing = $this->credentials[$credentialId] ?? null;

        if ($existing === null) {
            return;
        }

        $this->credentials[$credentialId] = new StoredCredential(
            credentialId: $existing->credentialId,
            userId: $existing->userId,
            algorithm: $existing->algorithm,
            publicKeyDer: $existing->publicKeyDer,
            ed25519PublicKey: $existing->ed25519PublicKey,
            signCount: $signCount,
            label: $existing->label,
            aaguid: $existing->aaguid,
            backupEligible: $existing->backupEligible,
            lastUsedAt: $at,
            createdAt: $existing->createdAt,
        );
    }

    public function delete(string $userId, string $credentialId): bool
    {
        if (($this->credentials[$credentialId] ?? null)?->userId !== $userId) {
            return false;
        }

        unset($this->credentials[$credentialId]);

        return true;
    }
}

/**
 * Only the handful of methods the challenge store touches are implemented; the
 * rest throw rather than returning a plausible value, so a fake that quietly
 * answers a call the subject should never make reports the coupling instead of
 * hiding it.
 *
 * @internal
 */
final class ArraySession implements SessionPort
{
    /** @var array<string, mixed> */
    public array $data = [];

    public function put(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function pull(string $key, mixed $default = null): mixed
    {
        $value = $this->data[$key] ?? $default;
        unset($this->data[$key]);

        return $value;
    }

    public function has(string $key): bool
    {
        return isset($this->data[$key]);
    }

    public function forget(string $key): void
    {
        unset($this->data[$key]);
    }

    public function all(): array
    {
        return $this->data;
    }

    public function start(?string $id = null): void {}

    public function id(): string
    {
        return 'test-session';
    }

    public function save(): void {}

    public function shouldPersist(): bool
    {
        return false;
    }

    public function push(string $key, mixed $value): void
    {
        throw new \LogicException('the challenge store must not push');
    }

    public function increment(string $key, int $by = 1): int
    {
        throw new \LogicException('the challenge store must not increment');
    }

    public function flush(): void
    {
        throw new \LogicException('the challenge store must not flush the session');
    }

    public function flash(string $key, mixed $value): void
    {
        throw new \LogicException('a challenge must outlive one request, so it is not flashed');
    }

    public function reflash(): void
    {
        throw new \LogicException('the challenge store must not reflash');
    }

    public function token(): string
    {
        throw new \LogicException('CSRF is a different mechanism');
    }

    public function regenerateToken(): void
    {
        throw new \LogicException('CSRF is a different mechanism');
    }

    public function regenerate(): void
    {
        throw new \LogicException('rotating the session id is the sign-in path, not this one');
    }

    public function invalidate(): void
    {
        throw new \LogicException('the challenge store must not invalidate the session');
    }
}
