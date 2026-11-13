<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Infrastructure\Sessions;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\Passkeys\API\Contracts\PasskeySessionStarter;
use Plugins\Passkeys\Domain\StoredCredential;

/**
 * The default: report the verified identity and create no session.
 *
 * It is deliberately NOT a silent no-op. A deployment that has enabled this
 * plugin and not bound its own {@see PasskeySessionStarter} has a sign-in
 * endpoint that verifies perfectly and leaves the user signed out, and the two
 * ways that could present are:
 *
 *   - a 200 with a plausible body, which looks like success and sends a
 *     developer looking at their frontend code for a bug that is not there;
 *   - this: a 200 whose body says `"authenticated": false` with the reason, and
 *     a warning in the log on every use.
 *
 * The second is noisier and much cheaper to diagnose, so the response carries
 * the explanation and the log records it once per sign-in.
 */
final class JsonSessionStarter implements PasskeySessionStarter
{
    public function __construct(private readonly ?LoggerPort $logger = null) {}

    public function start(StoredCredential $credential, Request $request): Response
    {
        $this->logger?->warning('passkeys.session_starter.not_bound', [
            'userId' => $credential->userId,
            'note'   => 'The assertion verified but no session was created. Bind '
                . 'Plugins\\Passkeys\\API\\Contracts\\PasskeySessionStarter to sign the user in.',
        ]);

        return Response::json([
            'authenticated' => false,
            'verified'      => true,
            'userId'        => $credential->userId,
            'credential'    => $credential->toArray(),
            'reason'        => 'The passkey verified, but this deployment has not bound a '
                . 'PasskeySessionStarter, so no session was created. See the plugin README.',
        ]);
    }
}
