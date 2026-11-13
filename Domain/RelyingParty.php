<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;

/**
 * Who the credentials belong to: the relying party id and the origins allowed
 * to use it.
 *
 * THE RELYING PARTY ID MUST NEVER CHANGE
 * --------------------------------------
 * Every credential's authenticator data carries `sha256(rpId)`, computed when
 * the credential was created. Change the id and every existing passkey stops
 * verifying — all of them, at once, with the symptom "nobody can log in" and
 * nothing in the logs pointing at a configuration change.
 *
 * So the id is the registrable domain and not the host: `example.com`, so that
 * `app.example.com` and `www.example.com` share credentials and moving the
 * sign-in page between them costs nothing.
 *
 * THE ORIGIN/ID RELATIONSHIP IS CHECKED HERE, AT CONSTRUCTION
 * -----------------------------------------------------------
 * The specification requires the relying party id to be a registrable suffix
 * of each origin's host. A deployment that gets this wrong — `rpId=example.com`
 * with an origin of `https://example.org` — produces a browser that refuses
 * every ceremony with a `SecurityError` on the CLIENT, where the server never
 * sees it. Checking at construction turns a silent, un-debuggable browser
 * refusal into a boot-time message naming both values.
 */
final readonly class RelyingParty
{
    /** @param list<string> $origins exact origins, e.g. `https://app.example.com` */
    public function __construct(
        public string $id,
        public string $name,
        public array $origins,
    ) {
        if (trim($id) === '') {
            throw WebAuthnException::misconfigured('The relying party id is empty. Set PASSKEYS_RP_ID.');
        }

        if ($origins === []) {
            throw WebAuthnException::misconfigured(
                'No allowed origins. Set PASSKEYS_ORIGINS, e.g. https://app.example.com.',
            );
        }

        foreach ($origins as $origin) {
            self::assertOriginCovers($origin, $id);
        }
    }

    /** sha256 of the id — what authenticator data is compared against. */
    public function idHash(): string
    {
        return hash('sha256', $this->id, true);
    }

    /**
     * Whether $origin's host is the relying party id or a subdomain of it.
     *
     * `localhost` is exempted because browsers treat it as a secure context for
     * development and an http origin there is normal. Nothing else is: a
     * deployment serving passkeys over plain http is one where the whole
     * ceremony can be observed and modified in transit.
     */
    private static function assertOriginCovers(string $origin, string $id): void
    {
        $parts = parse_url(rtrim($origin, '/'));

        if (!\is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            throw WebAuthnException::misconfigured(
                "The origin [{$origin}] is not a URL. It must include a scheme, e.g. https://app.example.com.",
            );
        }

        $host = strtolower($parts['host']);

        if ($parts['scheme'] !== 'https' && $host !== 'localhost' && $host !== '127.0.0.1') {
            throw WebAuthnException::misconfigured(
                "The origin [{$origin}] is not https. Browsers refuse WebAuthn outside a secure context.",
            );
        }

        $rpId = strtolower($id);

        // Either the host IS the id, or it ends with `.` + the id. The dot is
        // what stops `notexample.com` matching an id of `example.com`.
        if ($host !== $rpId && !str_ends_with($host, '.' . $rpId)) {
            throw WebAuthnException::misconfigured(
                "The origin [{$origin}] is not covered by the relying party id [{$id}]. "
                . 'The id must be the host or a parent domain of it, or the browser refuses every ceremony.',
            );
        }
    }
}
