<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\Passkeys\Domain\AttestationPolicy;
use Plugins\Passkeys\Domain\AuthenticatorData;
use Plugins\Passkeys\Domain\Base64Url;
use Plugins\Passkeys\Domain\Ceremony;
use Plugins\Passkeys\Domain\CoseAlgorithm;
use Plugins\Passkeys\Domain\CoseKey;
use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;
use Plugins\Passkeys\Domain\RelyingParty;

/**
 * The two ceremonies, against real keys and real signatures.
 *
 * THE SHAPE OF THIS SUITE IS THE TABLE IN {@see Ceremony}
 * ------------------------------------------------------
 * Each check in that class exists because dropping it makes something possible.
 * So for each one there is a test that drops it — a wrong challenge, a foreign
 * relying party, a flipped flag, a stale counter, a tampered signature — and
 * asserts that the ceremony refuses. A suite that only tested the happy path
 * would pass against an implementation that verified nothing at all.
 */
#[CoversClass(Ceremony::class)]
#[CoversClass(CoseKey::class)]
#[CoversClass(AuthenticatorData::class)]
#[CoversClass(RelyingParty::class)]
final class CeremonyTest extends TestCase
{
    private const CHALLENGE = 'Y2hhbGxlbmdlLWZvci10aGlzLWNlcmVtb255';

    // ── Registration: the happy path, on all three algorithms ─────────────────

    /** @return iterable<string, array{0: CoseAlgorithm}> */
    public static function algorithms(): iterable
    {
        yield 'ES256 (every platform authenticator)' => [CoseAlgorithm::ES256];
        yield 'RS256 (TPM-backed Windows Hello)'     => [CoseAlgorithm::RS256];
        yield 'EdDSA (Ed25519)'                      => [CoseAlgorithm::EdDSA];
    }

    #[DataProvider('algorithms')]
    public function test_a_registration_verifies_and_yields_a_usable_key(CoseAlgorithm $algorithm): void
    {
        $authenticator = new FakeAuthenticator($algorithm);

        $result = Ceremony::verifyRegistration(
            $authenticator->register(self::CHALLENGE),
            self::CHALLENGE,
            $this->relyingParty(),
        );

        self::assertSame($algorithm, $result->algorithm);
        self::assertSame(Base64Url::encode($authenticator->credentialId), $result->credentialId);
        self::assertNotSame('', $result->publicKeyDer);
        self::assertTrue($result->userVerified);
        self::assertTrue($result->backupEligible, 'a syncing passkey must be recorded as such');

        // The strongest assertion available: the key extracted from the
        // registration verifies a signature made by the authenticator's private
        // half, checked by OpenSSL or libsodium rather than by this plugin.
        $key     = $this->keyFrom($result);
        $message = random_bytes(64);

        self::assertTrue(
            $key->verify($message, $authenticator->sign($message)),
            'the stored key must verify a real signature from the matching private key',
        );
        self::assertFalse($key->verify($message, $authenticator->sign($message . 'x')));
    }

    /** The round trip through storage must not change the key's behaviour. */
    #[DataProvider('algorithms')]
    public function test_a_stored_key_still_verifies(CoseAlgorithm $algorithm): void
    {
        $authenticator = new FakeAuthenticator($algorithm);

        $result = Ceremony::verifyRegistration(
            $authenticator->register(self::CHALLENGE),
            self::CHALLENGE,
            $this->relyingParty(),
        );

        // As a repository would: base64 in a column, back out again.
        $rehydrated = CoseKey::fromStored(
            (string) base64_decode(base64_encode($result->publicKeyDer), true),
            $result->algorithm,
            (string) base64_decode(base64_encode($result->ed25519PublicKey), true),
        );

        $message = random_bytes(32);

        self::assertTrue($rehydrated->verify($message, $authenticator->sign($message)));
    }

    // ── Registration: every check ─────────────────────────────────────────────

    public function test_a_wrong_challenge_is_refused(): void
    {
        $this->assertRefused('challenge does not match', fn () => Ceremony::verifyRegistration(
            (new FakeAuthenticator())->register('a-different-challenge'),
            self::CHALLENGE,
            $this->relyingParty(),
        ));
    }

    public function test_a_credential_for_another_relying_party_is_refused(): void
    {
        $this->assertRefused('different relying party', fn () => Ceremony::verifyRegistration(
            (new FakeAuthenticator())->register(self::CHALLENGE, overrideRpId: 'evil.example'),
            self::CHALLENGE,
            $this->relyingParty(),
        ));
    }

    public function test_an_unknown_origin_is_refused(): void
    {
        $authenticator = new FakeAuthenticator(origin: 'https://phish.example.com');

        $this->assertRefused('not in the allowed list', fn () => Ceremony::verifyRegistration(
            $authenticator->register(self::CHALLENGE),
            self::CHALLENGE,
            new RelyingParty('example.com', 'Example', ['https://app.example.com']),
        ));
    }

    public function test_a_missing_user_presence_flag_is_refused(): void
    {
        $this->assertRefused('user-presence flag', fn () => Ceremony::verifyRegistration(
            (new FakeAuthenticator())->register(self::CHALLENGE, userPresent: false),
            self::CHALLENGE,
            $this->relyingParty(),
        ));
    }

    public function test_user_verification_is_only_required_when_asked_for(): void
    {
        $response = (new FakeAuthenticator())->register(self::CHALLENGE, userVerified: false);

        // Not required: accepted, because a security key with no PIN set is a
        // legitimate second factor.
        $result = Ceremony::verifyRegistration($response, self::CHALLENGE, $this->relyingParty());
        self::assertFalse($result->userVerified);

        $this->assertRefused('User verification was required', fn () => Ceremony::verifyRegistration(
            $response,
            self::CHALLENGE,
            $this->relyingParty(),
            requireUserVerification: true,
        ));
    }

    /**
     * A registration response is a different document from an authentication
     * one, and swapping them is the replay the `type` check exists to stop.
     */
    public function test_an_authentication_response_cannot_be_replayed_as_a_registration(): void
    {
        $authenticator = new FakeAuthenticator();

        $this->assertRefused('being replayed into the other', fn () => Ceremony::verifyRegistration(
            $authenticator->authenticate(self::CHALLENGE),
            self::CHALLENGE,
            $this->relyingParty(),
        ));
    }

    // ── Attestation policy ────────────────────────────────────────────────────

    /** The default: a platform authenticator's `none` is accepted. */
    public function test_no_attestation_is_accepted_by_default(): void
    {
        $result = Ceremony::verifyRegistration(
            (new FakeAuthenticator())->register(self::CHALLENGE, format: 'none'),
            self::CHALLENGE,
            $this->relyingParty(),
        );

        self::assertSame('none', $result->attestationFormat);
    }

    public function test_self_attestation_verifies_when_required(): void
    {
        $result = Ceremony::verifyRegistration(
            (new FakeAuthenticator())->register(self::CHALLENGE, format: 'packed'),
            self::CHALLENGE,
            $this->relyingParty(),
            AttestationPolicy::SelfAttested,
        );

        self::assertSame('packed', $result->attestationFormat);
    }

    public function test_requiring_self_attestation_refuses_none(): void
    {
        $this->assertRefused('requires self-attestation', fn () => Ceremony::verifyRegistration(
            (new FakeAuthenticator())->register(self::CHALLENGE, format: 'none'),
            self::CHALLENGE,
            $this->relyingParty(),
            AttestationPolicy::SelfAttested,
        ));
    }

    /**
     * A chain is REFUSED rather than ignored under this policy: reporting a
     * successful attestation check on a certificate nothing validated would be
     * worse than refusing, because an attacker can generate as many
     * self-signed certificates as they like.
     */
    public function test_a_certificate_chain_is_refused_rather_than_waved_through(): void
    {
        $this->expectException(WebAuthnException::class);

        try {
            Ceremony::verifyRegistration(
                (new FakeAuthenticator())->register(self::CHALLENGE, format: 'packed-x5c'),
                self::CHALLENGE,
                $this->relyingParty(),
                AttestationPolicy::SelfAttested,
            );
        } catch (WebAuthnException $e) {
            self::assertStringContainsString('Metadata Service', $e->reason);
            self::assertSame('unsupported', $e->kind);

            throw $e;
        }
    }

    /** With attestation ignored, the same credential is accepted. */
    public function test_a_certificate_chain_is_simply_not_looked_at_by_default(): void
    {
        $result = Ceremony::verifyRegistration(
            (new FakeAuthenticator())->register(self::CHALLENGE, format: 'packed-x5c'),
            self::CHALLENGE,
            $this->relyingParty(),
        );

        self::assertSame('packed', $result->attestationFormat);
    }

    // ── Authentication ────────────────────────────────────────────────────────

    #[DataProvider('algorithms')]
    public function test_an_assertion_verifies(CoseAlgorithm $algorithm): void
    {
        $authenticator = new FakeAuthenticator($algorithm);
        $stored        = $this->registerAndStore($authenticator);

        $result = Ceremony::verifyAssertion(
            $authenticator->authenticate(self::CHALLENGE, signCount: 5),
            self::CHALLENGE,
            $this->relyingParty(),
            $stored,
            storedSignCount: 1,
        );

        self::assertSame(5, $result->signCount);
        self::assertTrue($result->userVerified);
    }

    /**
     * An assertion result carries no credential id, because authenticator data
     * only contains one when the attested-credential flag is set — which
     * happens during registration and never during an assertion.
     *
     * Pinned as a test because the first version of this plugin DID expose the
     * field, read from authenticator data, and it was always `''`. A field
     * named `credentialId` holding an empty string reads as "this credential
     * has no id" rather than "this code looked in the wrong place".
     */
    public function test_an_assertion_result_has_no_credential_id_to_be_wrong_about(): void
    {
        self::assertFalse(
            property_exists(\Plugins\Passkeys\Domain\AssertionResult::class, 'credentialId'),
            'the caller already knows the id it looked the credential up by',
        );
    }

    /**
     * The check that carries everything else. Without it, anyone who knows a
     * credential id signs in as its owner.
     */
    public function test_a_tampered_signature_is_refused(): void
    {
        $authenticator = new FakeAuthenticator();
        $stored        = $this->registerAndStore($authenticator);

        $this->assertRefused('signature does not verify', fn () => Ceremony::verifyAssertion(
            $authenticator->authenticate(self::CHALLENGE, tamperSignature: random_bytes(72)),
            self::CHALLENGE,
            $this->relyingParty(),
            $stored,
            storedSignCount: 0,
        ));
    }

    /** A signature from a different key must not verify against this one. */
    public function test_another_authenticators_signature_is_refused(): void
    {
        $mine      = new FakeAuthenticator();
        $stored    = $this->registerAndStore($mine);
        $attacker  = new FakeAuthenticator(credentialId: $mine->credentialId);

        $this->assertRefused('signature does not verify', fn () => Ceremony::verifyAssertion(
            $attacker->authenticate(self::CHALLENGE),
            self::CHALLENGE,
            $this->relyingParty(),
            $stored,
            storedSignCount: 0,
        ));
    }

    public function test_a_replayed_assertion_is_refused_by_the_challenge(): void
    {
        $authenticator = new FakeAuthenticator();
        $stored        = $this->registerAndStore($authenticator);

        $captured = $authenticator->authenticate(self::CHALLENGE, signCount: 2);

        // The same bytes against a fresh challenge, which is what a replay is.
        $this->assertRefused('challenge does not match', fn () => Ceremony::verifyAssertion(
            $captured,
            'YS1uZXctY2hhbGxlbmdlLWVudGlyZWx5',
            $this->relyingParty(),
            $stored,
            storedSignCount: 1,
        ));
    }

    public function test_an_assertion_for_another_relying_party_is_refused(): void
    {
        $authenticator = new FakeAuthenticator();
        $stored        = $this->registerAndStore($authenticator);

        $this->assertRefused('different relying party', fn () => Ceremony::verifyAssertion(
            $authenticator->authenticate(self::CHALLENGE, overrideRpId: 'evil.example'),
            self::CHALLENGE,
            $this->relyingParty(),
            $stored,
            storedSignCount: 0,
        ));
    }

    public function test_an_assertion_from_an_unknown_origin_is_refused(): void
    {
        $authenticator = new FakeAuthenticator();
        $stored        = $this->registerAndStore($authenticator);

        $this->assertRefused('not in the allowed list', fn () => Ceremony::verifyAssertion(
            $authenticator->authenticate(self::CHALLENGE, overrideOrigin: 'https://evil.example.com'),
            self::CHALLENGE,
            $this->relyingParty(),
            $stored,
            storedSignCount: 0,
        ));
    }

    public function test_a_registration_response_cannot_be_replayed_as_an_assertion(): void
    {
        $authenticator = new FakeAuthenticator();
        $stored        = $this->registerAndStore($authenticator);

        $this->assertRefused('being replayed into the other', fn () => Ceremony::verifyAssertion(
            $authenticator->register(self::CHALLENGE),
            self::CHALLENGE,
            $this->relyingParty(),
            $stored,
            storedSignCount: 0,
        ));
    }

    // ── The signature counter ─────────────────────────────────────────────────

    /** A counter that did not advance means two copies of the key are in use. */
    public function test_a_stale_counter_is_refused_as_a_possible_clone(): void
    {
        $authenticator = new FakeAuthenticator();
        $stored        = $this->registerAndStore($authenticator);

        $this->assertRefused('may have been cloned', fn () => Ceremony::verifyAssertion(
            $authenticator->authenticate(self::CHALLENGE, signCount: 7),
            self::CHALLENGE,
            $this->relyingParty(),
            $stored,
            storedSignCount: 7,
        ));
    }

    /**
     * The branch that matters most for passkeys. A credential that syncs across
     * devices cannot keep a coherent counter, so iCloud Keychain and Google
     * Password Manager report 0 forever — and treating that as a clone would
     * reject every passkey on every sign-in.
     */
    public function test_a_counter_of_zero_on_both_sides_is_not_a_clone(): void
    {
        $authenticator = new FakeAuthenticator();
        $stored        = $this->registerAndStore($authenticator);

        $result = Ceremony::verifyAssertion(
            $authenticator->authenticate(self::CHALLENGE, signCount: 0),
            self::CHALLENGE,
            $this->relyingParty(),
            $stored,
            storedSignCount: 0,
        );

        self::assertSame(0, $result->signCount);
    }

    // ── userHandle ────────────────────────────────────────────────────────────

    public function test_the_user_handle_is_decoded_when_present(): void
    {
        $authenticator = new FakeAuthenticator();
        $stored        = $this->registerAndStore($authenticator);

        $result = Ceremony::verifyAssertion(
            $authenticator->authenticate(self::CHALLENGE, userHandle: 'user-42'),
            self::CHALLENGE,
            $this->relyingParty(),
            $stored,
            storedSignCount: 0,
        );

        self::assertSame('user-42', $result->userHandle);
    }

    public function test_an_absent_user_handle_is_an_empty_string(): void
    {
        $authenticator = new FakeAuthenticator();
        $stored        = $this->registerAndStore($authenticator);

        $result = Ceremony::verifyAssertion(
            $authenticator->authenticate(self::CHALLENGE),
            self::CHALLENGE,
            $this->relyingParty(),
            $stored,
            storedSignCount: 0,
        );

        self::assertSame('', $result->userHandle);
    }

    // ── Malformed input ───────────────────────────────────────────────────────

    /** @return iterable<string, array{0: array<string, mixed>}> */
    public static function malformedResponses(): iterable
    {
        yield 'empty'                      => [[]];
        yield 'no attestation object'       => [['clientDataJSON' => 'eyJ9']];
        yield 'clientDataJSON not base64url' => [['clientDataJSON' => '!!!!', 'attestationObject' => 'oA']];
        yield 'clientDataJSON not json'    => [[
            'clientDataJSON'    => Base64Url::encode('not json at all'),
            'attestationObject' => 'oA',
        ]];
        yield 'attestation object not cbor' => [[
            'clientDataJSON'    => Base64Url::encode('{"type":"webauthn.create","challenge":"x","origin":"y"}'),
            'attestationObject' => Base64Url::encode("\xFF\xFF\xFF"),
        ]];
        yield 'non-string field'           => [['clientDataJSON' => 42, 'attestationObject' => 'oA']];
    }

    #[DataProvider('malformedResponses')]
    public function test_malformed_input_raises_a_webauthn_exception_and_nothing_else(array $response): void
    {
        // Specifically NOT a TypeError, an ErrorException or a warning. Every
        // one of these arrives from an unauthenticated HTTP body, and the only
        // acceptable outcome is a refusal the controller can turn into a 422.
        $this->expectException(WebAuthnException::class);

        Ceremony::verifyRegistration($response, self::CHALLENGE, $this->relyingParty());
    }

    public function test_an_empty_challenge_can_never_be_satisfied(): void
    {
        // A ceremony whose stored challenge was lost must fail closed, not
        // accept a response whose challenge also happens to be empty.
        $this->assertRefused('challenge does not match', fn () => Ceremony::verifyRegistration(
            (new FakeAuthenticator())->register(''),
            '',
            $this->relyingParty(),
        ));
    }

    // ── Relying party configuration ───────────────────────────────────────────

    public function test_an_origin_not_covered_by_the_relying_party_id_is_a_configuration_error(): void
    {
        $this->assertRefused('not covered by the relying party id', fn () => new RelyingParty('example.com', 'Example', ['https://example.org']));
    }

    /** The dot is what stops `notexample.com` matching an id of `example.com`. */
    public function test_a_lookalike_domain_does_not_count_as_a_subdomain(): void
    {
        $this->assertRefused('not covered by the relying party id', fn () => new RelyingParty('example.com', 'Example', ['https://notexample.com']));
    }

    public function test_a_subdomain_origin_is_covered(): void
    {
        $party = new RelyingParty('example.com', 'Example', [
            'https://example.com',
            'https://app.example.com',
            'https://deep.app.example.com',
        ]);

        self::assertSame('example.com', $party->id);
    }

    public function test_plain_http_is_refused_except_on_localhost(): void
    {
        self::assertSame('localhost', (new RelyingParty('localhost', 'Dev', ['http://localhost:8000']))->id);

        $this->assertRefused('is not https', fn () => new RelyingParty('example.com', 'Example', ['http://app.example.com']));
    }

    public function test_an_empty_configuration_is_refused(): void
    {
        $this->assertRefused('No allowed origins', fn () => new RelyingParty('example.com', 'Example', []));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function relyingParty(): RelyingParty
    {
        return new RelyingParty('example.com', 'Example', ['https://app.example.com']);
    }

    /** Register, then rebuild the key the way a repository would. */
    private function registerAndStore(FakeAuthenticator $authenticator): CoseKey
    {
        return $this->keyFrom(Ceremony::verifyRegistration(
            $authenticator->register(self::CHALLENGE),
            self::CHALLENGE,
            $this->relyingParty(),
        ));
    }

    private function keyFrom(\Plugins\Passkeys\Domain\RegistrationResult $result): CoseKey
    {
        return CoseKey::fromStored($result->publicKeyDer, $result->algorithm, $result->ed25519PublicKey);
    }

    /**
     * Assert that $ceremony refuses, for the stated reason.
     *
     * The assertion is on `reason`, NOT on the message. The public message is
     * deliberately generic — identical for a wrong challenge, a foreign
     * relying party and a bad signature — so that an HTTP response cannot be
     * used as an oracle for which check failed. Asserting on it would
     * therefore prove only that something was refused, not that the right
     * thing was noticed, which would let a check be removed without any test
     * going red.
     */
    private function assertRefused(string $reasonFragment, \Closure $ceremony): void
    {
        try {
            $ceremony();
        } catch (WebAuthnException $e) {
            self::assertStringContainsString(
                $reasonFragment,
                $e->reason,
                "refused, but for the wrong reason: {$e->reason}",
            );

            return;
        }

        self::fail("the ceremony was accepted; expected a refusal mentioning [{$reasonFragment}]");
    }
}
