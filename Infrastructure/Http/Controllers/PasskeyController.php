<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Infrastructure\Http\Controllers;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use Plugins\Passkeys\API\Contracts\PasskeyServiceContract;
use Plugins\Passkeys\API\Contracts\PasskeySessionStarter;
use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;
use Plugins\Passkeys\Domain\StoredCredential;

/**
 * The six endpoints a passkey flow needs.
 *
 * WHY THE FAILURE IS CAUGHT HERE RATHER THAN LEFT TO THE ERROR PIPELINE
 * ---------------------------------------------------------------------
 * {@see WebAuthnException} extends PHP's `\DomainException`, not the kernel's,
 * so how the error pipeline would classify it is not something this plugin
 * should assume — and the consequence of assuming wrong is a 500 on what is an
 * ordinary, expected refusal of untrusted input, with a stack trace in the log
 * and an alert to go with it.
 *
 * Catching it makes the status explicit: 422, with the exception's PUBLIC
 * message. The reason has already been logged by the service, and is not in the
 * response — the public message is identical for a wrong challenge, a foreign
 * relying party and a bad signature, so the response cannot be used to work out
 * which check failed or whether a credential exists.
 */
final class PasskeyController
{
    public function __construct(
        private readonly PasskeyServiceContract $passkeys,
        private readonly PasskeySessionStarter $sessions,
    ) {}

    /** POST /auth/passkeys/register/options */
    public function registerOptions(Request $request): Response
    {
        $identity = $request->identity();

        if ($identity === null || $identity->isGuest()) {
            return Response::unauthorized();
        }

        return $this->attempt(fn (): Response => Response::json($this->passkeys->registrationOptions(
            $identity->userId,
            $identity->username !== '' ? $identity->username : $identity->userId,
            $identity->fullName,
        )));
    }

    /** POST /auth/passkeys/register */
    public function register(Request $request): Response
    {
        $identity = $request->identity();

        if ($identity === null || $identity->isGuest()) {
            return Response::unauthorized();
        }

        return $this->attempt(fn (): Response => Response::json([
            'credential' => $this->passkeys->completeRegistration(
                $identity->userId,
                self::credential($request),
                trim((string) $request->input('label', '')),
            )->toArray(),
        ], 201));
    }

    /**
     * POST /auth/passkeys/login/options
     *
     * Public, and the response is only a random challenge — but note that
     * passing a `userId` here would be an account-enumeration oracle, since the
     * `allowCredentials` list would be empty for an unknown user and populated
     * for a known one. So this endpoint never takes one: it always issues a
     * DISCOVERABLE request, which is also what a passkey sign-in wants.
     */
    public function loginOptions(Request $request): Response
    {
        return $this->attempt(fn (): Response => Response::json($this->passkeys->authenticationOptions()));
    }

    /** POST /auth/passkeys/login */
    public function login(Request $request): Response
    {
        return $this->attempt(function () use ($request): Response {
            $credential = $this->passkeys->completeAuthentication(self::credential($request));

            // Everything past here is the deployment's decision. See
            // PasskeySessionStarter.
            return $this->sessions->start($credential, $request);
        });
    }

    /** GET /auth/passkeys */
    public function index(Request $request): Response
    {
        $identity = $request->identity();

        if ($identity === null || $identity->isGuest()) {
            return Response::unauthorized();
        }

        return Response::json([
            'credentials' => array_map(
                static fn (StoredCredential $credential): array => $credential->toArray(),
                $this->passkeys->credentialsFor($identity->userId),
            ),
        ]);
    }

    /** DELETE /auth/passkeys/{id} */
    public function destroy(Request $request, string $id): Response
    {
        $identity = $request->identity();

        if ($identity === null || $identity->isGuest()) {
            return Response::unauthorized();
        }

        // 404 rather than 403 on someone else's credential: forget() is scoped
        // by user, so a false result means "not yours or not there", and
        // distinguishing those would confirm that an id exists.
        return $this->passkeys->forget($identity->userId, $id)
            ? Response::noContent()
            : Response::notFound();
    }

    /**
     * Run $work, turning a refused ceremony into a 422.
     *
     * @param \Closure(): Response $work
     */
    private function attempt(\Closure $work): Response
    {
        try {
            return $work();
        } catch (WebAuthnException $e) {
            return Response::unprocessable(['passkey' => $e->getMessage()]);
        }
    }

    /**
     * The credential object from the request body.
     *
     * Accepts the body being the credential itself — which is what
     * `JSON.stringify(credential)` produces — or wrapped in a `credential` key,
     * because a form-style client will usually nest it. Supporting both costs
     * three lines and removes a class of "it works in curl but not in the app".
     *
     * @return array<string, mixed>
     */
    private static function credential(Request $request): array
    {
        $wrapped = $request->input('credential');

        if (\is_array($wrapped)) {
            /** @var array<string, mixed> $wrapped */
            return $wrapped;
        }

        /** @var array<string, mixed> $all */
        $all = $request->all();

        return $all;
    }
}
