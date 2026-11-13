<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;

/**
 * `clientDataJSON` — what the BROWSER says happened.
 *
 * THE RAW BYTES ARE THE OBJECT'S MOST IMPORTANT PROPERTY
 * ------------------------------------------------------
 * The signature covers `authenticatorData ‖ sha256(clientDataJSON)`, and that
 * hash is over the bytes **exactly as they arrived**. So this class keeps them
 * and hashes them, and never re-encodes.
 *
 * Re-serialising the decoded array would be the single most destructive
 * imaginable bug here, and it would look completely reasonable:
 * `json_encode(json_decode($raw))` produces different bytes than the browser
 * sent — different key order, different escaping of `/` and non-ASCII — so the
 * hash would differ, so every signature would fail. The symptom is "passkeys
 * never work", with no clue pointing at the encoder.
 *
 * THE THREE CHECKS, AND WHAT EACH PREVENTS
 * ----------------------------------------
 * | Check | Without it |
 * |---|---|
 * | `type` | a registration response replays as an authentication, or vice versa |
 * | `challenge` | any captured response replays forever |
 * | `origin` | a credential works on any site that can reach the authenticator |
 *
 * The challenge comparison is `hash_equals`. A challenge is a one-time secret
 * the server issued, and comparing it with `===` leaks its prefix through
 * timing — which, for a value an attacker is trying to guess, is the textbook
 * case for a constant-time compare.
 */
final readonly class ClientData
{
    public const TYPE_CREATE = 'webauthn.create';
    public const TYPE_GET    = 'webauthn.get';

    private function __construct(
        /** As received. The hash is taken over these bytes and no others. */
        public string $raw,
        public string $type,
        /** base64url, as it appeared in the JSON. */
        public string $challenge,
        public string $origin,
        public bool $crossOrigin,
    ) {}

    public static function parse(string $json): self
    {
        try {
            /** @var mixed $decoded */
            $decoded = json_decode($json, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw WebAuthnException::malformed('clientDataJSON is not valid JSON: ' . $e->getMessage());
        }

        if (!\is_array($decoded)) {
            throw WebAuthnException::malformed('clientDataJSON is not a JSON object.');
        }

        foreach (['type', 'challenge', 'origin'] as $required) {
            if (!isset($decoded[$required]) || !\is_string($decoded[$required])) {
                throw WebAuthnException::malformed("clientDataJSON has no string `{$required}`.");
            }
        }

        /** @var array{type: string, challenge: string, origin: string, crossOrigin?: mixed} $decoded */
        return new self(
            raw: $json,
            type: $decoded['type'],
            challenge: $decoded['challenge'],
            origin: $decoded['origin'],
            crossOrigin: ($decoded['crossOrigin'] ?? false) === true,
        );
    }

    /** sha256 of the raw bytes — the second half of what was signed. */
    public function hash(): string
    {
        return hash('sha256', $this->raw, true);
    }

    /**
     * Run all three checks.
     *
     * @param list<string> $allowedOrigins exact origins, e.g. `https://app.example.com`
     * @throws WebAuthnException on any failure
     */
    public function assertValid(string $expectedType, string $expectedChallenge, array $allowedOrigins): void
    {
        if (!hash_equals($expectedType, $this->type)) {
            throw WebAuthnException::rejected(
                "clientDataJSON type is [{$this->type}], expected [{$expectedType}]. "
                . 'A response from one ceremony is being replayed into the other.',
            );
        }

        if ($expectedChallenge === '' || !hash_equals($expectedChallenge, $this->challenge)) {
            throw WebAuthnException::rejected(
                'The challenge does not match the one issued for this ceremony.',
            );
        }

        if (!self::originAllowed($this->origin, $allowedOrigins)) {
            throw WebAuthnException::rejected(
                "The origin [{$this->origin}] is not in the allowed list.",
            );
        }

        // A cross-origin ceremony means the call came from an iframe on another
        // site. Refused: nothing in a normal sign-in flow is cross-origin, and
        // permitting it is what makes a credential usable from a page the
        // application does not control.
        if ($this->crossOrigin) {
            throw WebAuthnException::rejected('The ceremony was performed cross-origin.');
        }
    }

    /**
     * Exact, case-sensitive origin matching against an allowlist.
     *
     * NOT a suffix or wildcard match, and that is the point. `str_ends_with`
     * against `.example.com` matches `https://evil-example.com` and
     * `https://example.com.attacker.net`; a wildcard on the scheme matches
     * `http://` and loses the transport. An origin is a short, closed,
     * deployment-known list, so an allowlist costs nothing and has no edge
     * cases.
     *
     * The one normalisation applied is a trailing slash, which some browsers
     * historically appended.
     *
     * @param list<string> $allowed
     */
    private static function originAllowed(string $origin, array $allowed): bool
    {
        $candidate = rtrim($origin, '/');

        foreach ($allowed as $permitted) {
            if (hash_equals(rtrim($permitted, '/'), $candidate)) {
                return true;
            }
        }

        return false;
    }
}
