<?php

declare(strict_types=1);

namespace Plugins\Passkeys\API\Contracts;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use Plugins\Passkeys\Domain\StoredCredential;

/**
 * What happens AFTER an assertion verifies.
 *
 * WHY THIS IS INVERTED RATHER THAN DONE HERE
 * ------------------------------------------
 * Establishing a session correctly is not a one-liner, and the evidence is in
 * the Social Auth plugin, which solved the same problem first. Its controller
 * comments on why it does NOT call `AuthServiceContract::startSession()`:
 *
 *   > A bare AuthServiceContract::startSession() carries none of those — a
 *   > signed-in person with no role on a tenant host.
 *
 * What it calls instead reaches a guard that loads the account
 * membership-aware for the request's tenant, with its roles and permissions and
 * its device-session row — and it reaches it through
 * `Project\Http\Controllers\ApiController`, a base class in the PROJECT layer.
 *
 * So the correct sign-in depends on facilities a deployment owns: which guard,
 * which tenant resolution, whether a device-session row is wanted, where to
 * redirect. A passkey plugin that picked one would be right for one deployment
 * and quietly wrong for the rest — and "quietly" is the problem, because the
 * symptom is a user who appears signed in and has no permissions.
 *
 * This plugin therefore proves possession of the credential and stops. The
 * default implementation returns the verified identity as JSON and says
 * plainly that no session was created, so a deployment that has not wired this
 * up finds out immediately rather than shipping a sign-in that does not sign
 * anyone in.
 */
interface PasskeySessionStarter
{
    /**
     * Turn a verified credential into whatever this deployment calls being
     * signed in.
     *
     * The credential has ALREADY been verified when this is called: the
     * signature checked out against the stored key, the challenge was issued to
     * this session and has been spent, the relying party and origin matched,
     * and the counter advanced. `$credential->userId` is the server's own
     * record of the owner, not a client claim, and is safe to sign in as.
     */
    public function start(StoredCredential $credential, Request $request): Response;
}
