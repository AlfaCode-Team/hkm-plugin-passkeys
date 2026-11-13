<?php

declare(strict_types=1);

namespace Plugins\Passkeys;

use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Contracts\ModuleContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\EventBus;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Cli\CliPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\HttpPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Worker\WorkerPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\ClockPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\DatabasePort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SessionPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SystemClock;
use Plugins\Passkeys\API\Contracts\PasskeyServiceContract;
use Plugins\Passkeys\API\Contracts\PasskeySessionStarter;
use Plugins\Passkeys\API\Contracts\PasskeyStoreContract;
use Plugins\Passkeys\Application\Services\ChallengeStore;
use Plugins\Passkeys\Application\Services\PasskeyService;
use Plugins\Passkeys\Domain\AttestationPolicy;
use Plugins\Passkeys\Domain\RelyingParty;
use Plugins\Passkeys\Infrastructure\Cli\PasskeyDoctorCommand;
use Plugins\Passkeys\Infrastructure\Http\Controllers\PasskeyController;
use Plugins\Passkeys\Infrastructure\Persistence\DatabasePasskeyStore;
use Plugins\Passkeys\Infrastructure\Sessions\JsonSessionStarter;

/**
 * Passkeys — WebAuthn registration and authentication.
 *
 * Solves `auth.passkeys`. No vendor WebAuthn library: the ceremonies are a CBOR
 * decode, a COSE-to-DER conversion and two signature checks, and the checks ARE
 * the security — so they belong in a repository that can be read alongside the
 * tests that pin them, rather than behind a dependency whose defaults would
 * have to be documented and tracked here anyway.
 *
 * `PASSKEYS_RP_ID` IS REQUIRED WITH NO DEFAULT, deliberately, which means
 * enabling this plugin fails the boot until it is set. That is the intended
 * behaviour rather than an oversight: every credential's authenticator data
 * carries `sha256(rpId)`, so a wrong value is not a misconfiguration that can
 * be corrected later — it is credentials bound to an id nobody will send again.
 * Changing it afterwards invalidates every passkey at once, with the symptom
 * "nobody can log in" and nothing in the logs pointing at it. A loud failure at
 * boot is the cheapest moment for that to be wrong.
 */
final class Provider implements ModuleContract
{
    public function solves(): string
    {
        return 'auth.passkeys';
    }

    /**
     * @return list<string>
     */
    public function requires(): array
    {
        return [
            // DatabasePort for the credential table.
            'database.management',
            // SessionPort: a challenge must be bound to a browser, not to
            // whoever holds an id. See ChallengeStore.
            'session.management',
            // So `$request->identity()` is populated on the management routes.
            'auth.identity',
            // The plugin that PUBLISHES the `auth` and `throttle` filter
            // aliases this plugin's routes name. Declaring `requiresFilters`
            // alone is not enough: that check compares against the
            // `providesFilters` of REGISTERED modules, so without this entry
            // the provider need not be in the module list at all and the boot
            // fails with "which no registered module provides" — which is what
            // `ground probe` reported before this line existed.
            'http.security_filters',
        ];
    }

    /**
     * {@see PasskeySessionStarter} is NOT listed.
     *
     * `exposes` names what this plugin binds for others to resolve, and that
     * contract runs the other way: a project implements it and binds it, and
     * this plugin looks for it. Listing it would make `ground probe` right to
     * fail, since it checks that every exposed contract resolves and there is
     * nothing to resolve in a deployment that has not supplied one.
     *
     * @return list<class-string>
     */
    public function exposes(): array
    {
        return [
            PasskeyServiceContract::class,
            PasskeyStoreContract::class,
        ];
    }

    public function register(ModuleContainer $container): void
    {
        $container->bindInternal(
            DatabasePasskeyStore::class,
            static fn ($c): DatabasePasskeyStore => new DatabasePasskeyStore($c->make(DatabasePort::class)),
        );

        $container->bindInternal(ChallengeStore::class, static fn ($c): ChallengeStore => new ChallengeStore(
            session: $c->make(SessionPort::class),
            lifetime: max(30, (int) (env('PASSKEYS_CHALLENGE_TTL') ?: 120)),
        ));

        $container->bind(
            PasskeyStoreContract::class,
            static fn ($c): PasskeyStoreContract => $c->make(DatabasePasskeyStore::class),
        );

        $container->bind(PasskeyServiceContract::class, static fn ($c): PasskeyServiceContract => new PasskeyService(
            store: $c->make(PasskeyStoreContract::class),
            challenges: $c->make(ChallengeStore::class),
            relyingParty: self::relyingParty(),
            clock: self::clock($c),
            attestation: AttestationPolicy::fromName((string) (env('PASSKEYS_ATTESTATION') ?? '')),
            requireUserVerification: self::flag(env('PASSKEYS_REQUIRE_USER_VERIFICATION')),
            maxPerUser: max(1, (int) (env('PASSKEYS_MAX_PER_USER') ?: 20)),
            logger: self::logger($c),
        ));

        // Bound explicitly rather than autowired, because the session starter
        // is resolved by PROBE: autowiring would need the contract to be
        // bound, and binding it here would shadow a project's own.
        $container->bind(PasskeyController::class, static fn ($c): PasskeyController => new PasskeyController(
            $c->make(PasskeyServiceContract::class),
            self::sessionStarter($c),
        ));
    }

    public function boot(HttpPipeline $http, CliPipeline $cli, WorkerPipeline $worker, EventBus $events): void
    {
        $cli->command(PasskeyDoctorCommand::class);

        // No pipeline hook and no filter published. The routes declare the
        // `auth` and `throttle` filters they need through module.json
        // `requiresFilters`, so a deployment missing the plugin that provides
        // them fails at boot with a message naming the alias — rather than at
        // the moment someone tries to sign in.
    }

    /**
     * Built from configuration, and it THROWS on a bad one.
     *
     * The constructor checks that each origin is covered by the relying party
     * id, because a mismatch makes the browser refuse every ceremony with a
     * client-side SecurityError the server never sees. Failing here turns an
     * un-debuggable browser refusal into a message naming both values.
     */
    private static function relyingParty(): RelyingParty
    {
        $origins = array_values(array_filter(array_map(
            'trim',
            explode(',', (string) (env('PASSKEYS_ORIGINS') ?? '')),
        ), static fn (string $origin): bool => $origin !== ''));

        $name = trim((string) (env('PASSKEYS_RP_NAME') ?? ''));

        return new RelyingParty(
            id: trim((string) (env('PASSKEYS_RP_ID') ?? '')),
            name: $name !== '' ? $name : trim((string) (env('APP_NAME') ?? 'Application')),
            origins: $origins,
        );
    }

    /**
     * A project's own, or the one that signs nobody in and says so.
     *
     * Probed with has(), not make(): nothing in this plugin binds the contract,
     * so a positive answer means the project did.
     */
    private static function sessionStarter(mixed $container): PasskeySessionStarter
    {
        try {
            if ($container->has(PasskeySessionStarter::class)) {
                $bound = $container->make(PasskeySessionStarter::class);

                if ($bound instanceof PasskeySessionStarter) {
                    return $bound;
                }
            }
        } catch (\Throwable) {
            // A broken project implementation must not take the ceremony
            // endpoints down with it; the default reports the verification and
            // logs that no session was made.
        }

        return new JsonSessionStarter(self::logger($container));
    }

    /** The kernel's SystemClock when no ClockPort is bound. */
    private static function clock(mixed $container): ClockPort
    {
        try {
            return $container->has(ClockPort::class) ? $container->make(ClockPort::class) : new SystemClock();
        } catch (\Throwable) {
            return new SystemClock();
        }
    }

    private static function logger(mixed $container): ?LoggerPort
    {
        try {
            return $container->has(LoggerPort::class) ? $container->make(LoggerPort::class) : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /** `true`/`1`/`yes`/`on` — anything else is false, including a typo. */
    private static function flag(mixed $value): bool
    {
        return \in_array(strtolower(trim((string) ($value ?? ''))), ['1', 'true', 'yes', 'on'], true);
    }
}
