# Passkeys — WebAuthn for the HKM Kernel

Solves `auth.passkeys`. Registration and authentication with passkeys and
security keys, verified natively.

No vendor WebAuthn library. The ceremonies are a CBOR decode, a COSE-to-DER key
conversion and two signature checks — and **the checks are the security**, so
they belong in a repository that can be read next to the tests that pin them,
rather than behind a dependency whose defaults would have to be documented and
tracked here anyway.

```bash
hkm plugins enable passkeys
hkm cli passkeys:doctor          # before a user meets the configuration
hkm cli migrate                  # creates passkey_credentials
```

## Two things to know before enabling it

**`PASSKEYS_RP_ID` is required with no default, so the boot fails until it is
set.** That is intended. Every credential's authenticator data carries
`sha256(rpId)`, computed when the credential was created — so a wrong value is
not a misconfiguration you correct later, it is credentials bound to an id
nobody will ever send again. Changing it afterwards invalidates **every passkey
at once**, with the symptom "nobody can log in" and nothing in the logs pointing
at it. Use the registrable domain (`example.com`, not `app.example.com`) so every
host under it shares credentials.

**This plugin does not sign anyone in.** `POST /auth/passkeys/login` verifies the
assertion and hands the credential to a `PasskeySessionStarter`; the default one
reports the verified identity and creates no session. See
[Signing the user in](#signing-the-user-in) — it is two lines, and the reason it
is yours to write is in that section.

## What a successful ceremony actually proves

Not "this is a YubiKey". The claim is:

> someone, in possession of the private key for this credential id, signed a
> challenge **this server issued moments ago**, naming **this relying party**,
> from an origin we permit.

Each clause is a check, and dropping any one collapses the claim:

| Dropped | What becomes possible |
|---|---|
| signature | anyone who knows a credential id signs in as its owner |
| challenge | a captured response replays forever |
| rpIdHash | a credential from another site is accepted here |
| origin | a page the application does not control runs the ceremony |
| type | a registration response is replayed as an authentication |
| user presence | a credential is used with nobody at the keyboard |

None is defensive programming. They are the protocol, and each has a test that
removes it and asserts the refusal.

## Attestation: why `none` is the default

Attestation answers a question most applications are not asking — "is this
really a YubiKey 5, model such-and-such" — and answering it properly needs the
FIDO Metadata Service, certificate-chain validation, and a policy for when a
vendor root expires. That is a subsystem, not a check.

For passkeys it mostly cannot be answered anyway: iCloud Keychain, Google
Password Manager and Windows Hello return `none` or self-attestation **by
design**, because a syncing credential is not bound to one device and attesting
to hardware would be a lie. The W3C's own guidance is that a relying party with
no hardware-allowlist requirement should request `attestation: "none"`.

`PASSKEYS_ATTESTATION=self` adds self-attestation — the authenticator signs the
registration with the key being registered — and **rejects `none`**, so it will
turn away some platform authenticators. That is the trade, stated so it can be
made deliberately.

Full attestation is deliberately **absent rather than half-built**. A chain
validated against no trusted roots is not a weaker check; it is a check that
reports success for any self-signed certificate an attacker cares to generate.
A credential carrying `x5c` is therefore refused under `self`, not waved
through.

## The signature counter, and why passkeys break the obvious check

An authenticator's counter increases with every assertion, so a value that did
not advance means two copies of the private key are in use — a cloned hardware
key.

**Both zero means no counter, not a replay.** A credential that syncs across
devices cannot keep a coherent counter, so iCloud Keychain and Google Password
Manager report `0` forever. Treating that as a clone would reject every passkey
on every sign-in. The check is skipped when the authenticator declines to count,
and enforced when it does.

## Why this parses rather than pattern-matches

Every regex-based WebAuthn shortcut fails the same way: the pattern and the
browser read different strings. And the parsing itself is where the hostile
input lands, so the decoder refuses what CTAP2 forbids rather than being
generous:

| Refused | Why |
|---|---|
| indefinite lengths | CTAP2 forbids them; supporting them means tracking nesting across a break marker, which is how such parsers get confused about where an item ends |
| CBOR tags | a tag wrapping a byte string is a second way to express the same value, so two parsers can disagree about what a message said |
| duplicate map keys | not forbidden by the format. One parser keeps the first value, another the last — so one attestation object says two different things depending on who reads it |
| trailing bytes | "parse the beginning and ignore the rest" is how a parser agrees with an attacker about a prefix and with nobody about the whole |
| nesting past 12 deep | PHP has no tail calls, so this is a segmentation fault rather than an exception — it takes the worker down instead of returning a 422 |

Canonical **ordering**, which CTAP2 also requires, is *not* enforced: a
non-canonical order cannot create a disagreement about meaning, and real
authenticators have shipped with ordering bugs, so enforcing it would reject
working hardware for nothing.

### The COSE label collision

A COSE_Key is a CBOR map with negative integer labels, and the same label means
different things per key type:

```
-1  crv   curve (EC2/OKP)        -1  n   modulus (RSA)
-2  x     coordinate / pubkey    -2  e   exponent (RSA)
```

So the key type is established **before** any other label is read. A parser that
reads `-1` first and asks what it means afterwards can be handed an RSA key it
interprets as a curve identifier.

### Algorithms

ES256, RS256 and EdDSA — every passkey in existence. Absent deliberately: `-65535`
is RS1, RSASSA-PKCS1-v1_5 with **SHA-1**, in the registry because old TPMs used
it. SHA-1 is broken for collision resistance and an authenticator offering it is
one to decline, for the same reason a JWT library declines `alg: none`.

## Signing the user in

`completeAuthentication()` returns the credential and establishes nothing,
because the correct sign-in is not interchangeable across deployments — and the
evidence is in this workspace. The Social Auth plugin solved the same problem
first, and its controller comments on why it does **not** call
`AuthServiceContract::startSession()`:

> A bare AuthServiceContract::startSession() carries none of those — a signed-in
> person with no role on a tenant host.

What it calls instead reaches a guard that loads the account membership-aware for
the request's tenant, with its roles, permissions and device-session row — through
`Project\Http\Controllers\ApiController`, a base class in the **project layer**.

So a correct sign-in depends on things a deployment owns: which guard, which
tenant resolution, whether a device-session row is wanted, where to redirect. A
passkey plugin that picked one would be right for one deployment and quietly
wrong for the rest — and *quietly* is the problem, because the symptom is a user
who appears signed in and has no permissions.

Bind your own:

```php
use Plugins\Passkeys\API\Contracts\PasskeySessionStarter;

final class ProjectPasskeyLogin implements PasskeySessionStarter
{
    public function start(StoredCredential $credential, Request $request): Response
    {
        // The SAME path a password login takes — whatever that is here.
        if ($this->auth('web')->loginUsingId($credential->userId) === false) {
            return Response::forbidden();
        }

        return Response::json(['authenticated' => true]);
    }
}
```

Until you do, `/auth/passkeys/login` returns `"authenticated": false` with the
reason and logs a warning on every use. Noisy on purpose: the alternative is a
200 with a plausible body, which looks like success and sends a developer
looking at their frontend for a bug that is not there.

## Routes

| | | |
|---|---|---|
| `POST` | `/auth/passkeys/register/options` | `auth` |
| `POST` | `/auth/passkeys/register` | `auth` |
| `POST` | `/auth/passkeys/login/options` | `throttle:30,1` |
| `POST` | `/auth/passkeys/login` | `throttle:30,1` |
| `GET` | `/auth/passkeys` | `auth` |
| `DELETE` | `/auth/passkeys/{id}` | `auth` |

`login/options` takes **no user id**, ever. Accepting one would be an
account-enumeration oracle: `allowCredentials` would be empty for an unknown user
and populated for a known one. It always issues a discoverable request, which is
also what a passkey sign-in wants.

`requires` includes `http.security_filters` and not only `requiresFilters`.
Declaring the latter alone is not enough — that check compares against the
`providesFilters` of **registered** modules, so without the `requires` entry the
providing plugin need not be in the module list and the boot fails with "which no
registered module provides". `ground probe` reported exactly that before the
entry existed.

## Storage

One table, `passkey_credentials`, in the sign-in database — central, plus an
identical copy in `database/tenant-template/`, following `auth_sessions`.

Two decisions that are not obvious:

- **The unique index is on a hash of the credential id.** An id may be up to 1023
  bytes, which base64url-encodes to ~1364 characters — past MySQL's index limit
  and past where any engine indexes well. Real ids are 16–64 bytes, so a short
  column would work *almost* always: the failure would arrive from one unusual
  authenticator, in production, as a truncated id matching the wrong row.
- **The public key is base64 in a text column, not a blob.** Binary columns are
  where MySQL, PostgreSQL and SQLite disagree most through PDO, with silent
  charset mangling as the failure. The cost is 33% more bytes on a few hundred;
  the benefit is one migration that works on all three.

Credential ids are unique **globally, not per user** — an authentication has no
user to scope the lookup by, which is what makes a usernameless sign-in possible.

## Config

| Env | Default | |
|---|---|---|
| `PASSKEYS_RP_ID` | **required** | the registrable domain. Never change it |
| `PASSKEYS_ORIGINS` | **required** | comma-separated exact origins, e.g. `https://app.example.com` |
| `PASSKEYS_RP_NAME` | `APP_NAME` | what the authenticator shows the user |
| `PASSKEYS_ATTESTATION` | `none` | `none` \| `self` |
| `PASSKEYS_REQUIRE_USER_VERIFICATION` | `false` | set it if passkeys are the **only** factor — otherwise a key with no PIN signs in on possession alone |
| `PASSKEYS_MAX_PER_USER` | `20` | keeps `excludeCredentials` small enough for authenticators to accept |
| `PASSKEYS_CHALLENGE_TTL` | `120` | seconds |

`passkeys:doctor` checks the id/origins relationship, which is the only thing a
deployment can get wrong **invisibly**: a mismatch makes the browser refuse with
a `SecurityError` before any request is sent, so there is nothing in the
application log, nothing in the access log, and no clue beyond a user saying "the
button does nothing".

## Tests

146 tests. What makes them worth something:

**Real cryptography, not fixtures.** `FakeAuthenticator` generates real keys with
OpenSSL and libsodium, builds real authenticator data, and produces real
signatures — across all three algorithms. A captured response pasted in as a
fixture would prove the parser handles one device once, and could not be varied
to test a wrong challenge, a flipped flag, a stale counter or a tampered
signature.

**The crypto path is not self-referential.** Signatures are produced by OpenSSL
and libsodium and verified by OpenSSL and libsodium. If the COSE-to-DER
conversion were wrong by one byte, they would reject it — they have no knowledge
of what this plugin intended.

**The DER encoder is compared byte-for-byte with OpenSSL's own serialisation** of
the same key, which is stronger than "OpenSSL accepted it": OpenSSL is tolerant
about some malformations and will load a key whose coordinates have shifted, then
fail every verification afterwards for reasons that look like a signature
problem.

**The CBOR decoder is checked against hand-written RFC 8949 vectors**, because
the test suite contains its own CBOR *encoder* and a round-trip through it would
pass with a matching bug on both sides.

**What is not tested: a real authenticator.** Every protocol rule, every refusal
and every algorithm is covered, and the claim that a real iPhone's bytes parse
needs a real iPhone. Register one key by hand before trusting a deployment.

## License

MIT.
