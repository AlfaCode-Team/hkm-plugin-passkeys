<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain\Exceptions;

/**
 * A ceremony that did not verify.
 *
 * ONE EXCEPTION TYPE, AND A DELIBERATELY VAGUE PUBLIC MESSAGE
 * -----------------------------------------------------------
 * Every failure in a WebAuthn ceremony is the same thing to the caller — the
 * assertion did not verify, so nobody is signed in — and distinguishing them in
 * the HTTP response would hand an attacker a decision oracle. "Unknown
 * credential id" and "signature did not verify" are different facts about
 * whether a credential exists, and the second is only reachable by someone who
 * knows a real id.
 *
 * So {@see self::$reason} carries the detail for the log and
 * {@see self::getMessage()} stays generic. A controller returns the message; an
 * audit trail records the reason.
 *
 * `DomainException` as the base is deliberate too: a failed ceremony is an
 * expected outcome of untrusted input, not an infrastructure fault, and the
 * kernel's error pipeline maps it to a 422 with `info` severity rather than
 * paging anyone.
 */
final class WebAuthnException extends \DomainException
{
    private function __construct(
        string $message,
        /** The detail, for the log only. Never returned to the client. */
        public readonly string $reason,
        public readonly string $kind,
    ) {
        parent::__construct($message);
    }

    /** The input was not the shape WebAuthn describes. */
    public static function malformed(string $reason): self
    {
        return new self('The credential could not be read.', $reason, 'malformed');
    }

    /**
     * The input parsed but failed a check — challenge, origin, rpId, flags,
     * signature, counter.
     */
    public static function rejected(string $reason): self
    {
        return new self('The credential could not be verified.', $reason, 'rejected');
    }

    /**
     * The DEPLOYMENT is wrong, not the credential.
     *
     * The only case whose public message is the reason, and the exception to
     * the vagueness rule above rather than a lapse in it. The generic message
     * exists so an attacker cannot use the response as an oracle for which
     * check failed — and a misconfigured relying party id has no attacker. It
     * has an operator, who needs to be told which variable is wrong.
     *
     * Reported as "The credential could not be verified." it is actively
     * misleading: `ground probe` showed exactly that, a message about
     * credentials for a problem that was entirely in `PASSKEYS_ORIGINS`, which
     * is how an afternoon gets spent reading the wrong code.
     */
    public static function misconfigured(string $reason): self
    {
        return new self('Passkeys are not configured correctly: ' . $reason, $reason, 'misconfigured');
    }

    /**
     * Something this implementation does not support, such as an unknown COSE
     * algorithm.
     *
     * Separate from `rejected` because the two want different responses from an
     * operator: a rejection is working as designed, while this one means a real
     * authenticator met a gap and the gap should probably be closed.
     */
    public static function unsupported(string $reason): self
    {
        return new self('This security key is not supported.', $reason, 'unsupported');
    }
}
