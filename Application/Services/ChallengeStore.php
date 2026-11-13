<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SessionPort;
use Plugins\Passkeys\Domain\Base64Url;
use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;

/**
 * Issues a challenge and lets it be used exactly once.
 *
 * WHY THE SESSION AND NOT A CACHE KEY
 * -----------------------------------
 * A challenge could be stored in `CachePort` under a random id handed to the
 * client, and that would be simpler. It would also be wrong: the challenge
 * would then be bound to whoever holds the id rather than to a browser, so an
 * attacker could ask the application for a challenge, pass it to a victim's
 * authenticator through some other channel, and complete the ceremony
 * themselves with the response.
 *
 * Binding it to the session means the response must come back on the same
 * cookie the challenge was issued to.
 *
 * CONSUMPTION IS DESTRUCTIVE, and that is the replay defence rather than a
 * tidiness measure. A challenge that survives its own use can be replayed for
 * as long as the session lives: capture one successful response and resubmit it
 * whenever you like. `consume()` therefore forgets the value BEFORE returning
 * it, so even a verification that throws has spent the challenge.
 *
 * EXPIRY IS SHORT. A ceremony is a user tapping a key, which takes seconds. Two
 * minutes is generous for that and short enough that a challenge captured from
 * a log or a proxy is useless by the time anyone reads it.
 */
final class ChallengeStore
{
    public const PURPOSE_REGISTER = 'create';
    public const PURPOSE_LOGIN    = 'get';

    private const PREFIX = 'passkeys.challenge.';

    /**
     * Challenge length in bytes, never below the specification's floor.
     *
     * Not a promoted property, because the floor has to be applied: a
     * configured `0` would otherwise reach `random_bytes()` and throw, turning
     * a harmless misconfiguration into a 500 on every sign-in — and a
     * configured `4` would be accepted silently, which is worse, because a
     * 32-bit challenge is guessable and nothing would look wrong.
     *
     * @var int<16, max>
     */
    private readonly int $length;

    public function __construct(
        private readonly SessionPort $session,
        /** Seconds a challenge remains usable. */
        private readonly int $lifetime = 120,
        /** Thirty-two by default: the cost is nothing and the value's only job is to be unguessable. */
        int $length = 32,
    ) {
        $this->length = max(16, $length);
    }

    /** A fresh challenge, stored against this session. */
    public function issue(string $purpose): string
    {
        $challenge = Base64Url::encode(random_bytes($this->length));

        $this->session->put(self::PREFIX . $purpose, [
            'value'   => $challenge,
            'expires' => time() + $this->lifetime,
        ]);

        return $challenge;
    }

    /**
     * The stored challenge, removed in the same breath.
     *
     * @throws WebAuthnException when there is none, or it has expired
     */
    public function consume(string $purpose): string
    {
        $key = self::PREFIX . $purpose;

        // pull() reads and forgets in one call, which is what makes this
        // one-time rather than "one-time if nothing throws later".
        $stored = $this->session->pull($key);

        if (!\is_array($stored) || !\is_string($stored['value'] ?? null) || !\is_int($stored['expires'] ?? null)) {
            throw WebAuthnException::rejected(
                'No challenge was issued for this session, or it has already been used. '
                . 'Request a fresh one before completing the ceremony.',
            );
        }

        if ($stored['expires'] < time()) {
            throw WebAuthnException::rejected('The challenge has expired. Request a fresh one.');
        }

        return $stored['value'];
    }
}
