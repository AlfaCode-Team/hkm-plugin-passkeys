<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use Plugins\Passkeys\Domain\AttestationPolicy;
use Plugins\Passkeys\Domain\Exceptions\WebAuthnException;
use Plugins\Passkeys\Domain\RelyingParty;

/**
 * passkeys:doctor — check the configuration before a user meets it.
 *
 * WHY THIS IS THE ONE COMMAND THIS PLUGIN SHIPS
 * ---------------------------------------------
 * Because the relying party id and the origin list are the only things a
 * deployment can get wrong in a way that is invisible from the server. A
 * mismatch between them makes the BROWSER refuse the ceremony with a
 * `SecurityError` before any request is sent — so there is nothing in the
 * application log, nothing in the access log, and no clue beyond a user saying
 * "the button does nothing".
 *
 * The `RelyingParty` constructor already refuses a bad combination, so in a
 * running application this is caught at boot. This command is for the moment
 * before that: checking a value in a deploy script or an `.env` review, where
 * the answer costs a second rather than a failed release.
 */
final class PasskeyDoctorCommand extends AbstractCommand
{
    protected function configure(): void
    {
        $this->name        = 'passkeys:doctor';
        $this->description = 'Check the passkey relying party configuration';
    }

    protected function handle(): int
    {
        $this->section('Passkeys');

        $rpId    = trim((string) (env('PASSKEYS_RP_ID') ?? ''));
        $origins = (string) (env('PASSKEYS_ORIGINS') ?? '');

        $this->muted('PASSKEYS_RP_ID   : ' . ($rpId !== '' ? $rpId : '(unset)'));
        $this->muted('PASSKEYS_ORIGINS : ' . ($origins !== '' ? $origins : '(unset)'));
        $this->muted('Attestation      : ' . AttestationPolicy::fromName(
            (string) (env('PASSKEYS_ATTESTATION') ?? ''),
        )->value);
        $this->newLine();

        if ($rpId === '' || $origins === '') {
            $this->error('Both PASSKEYS_RP_ID and PASSKEYS_ORIGINS must be set.');
            $this->muted('  PASSKEYS_RP_ID is the registrable domain — example.com, not app.example.com,');
            $this->muted('  so that every host under it shares credentials.');
            $this->muted('  PASSKEYS_ORIGINS is a comma-separated list of exact origins.');

            return self::FAILURE;
        }

        $list = array_values(array_filter(array_map('trim', explode(',', $origins))));

        try {
            new RelyingParty($rpId, 'check', $list);
        } catch (WebAuthnException $e) {
            $this->error('The configuration is not usable.');
            $this->muted($e->reason);

            return self::FAILURE;
        }

        $this->success('Configuration is consistent.');

        foreach ($list as $origin) {
            $this->muted("  {$origin} is covered by {$rpId}");
        }

        $this->newLine();
        $this->warning('Not checked here: that the relying party id has never changed.');
        $this->muted('  Every stored credential carries sha256(rpId) from the day it was created, so');
        $this->muted('  changing this value invalidates every existing passkey at once. If this is an');
        $this->muted('  established deployment, confirm the value against the one credentials were made with.');

        return self::SUCCESS;
    }
}
