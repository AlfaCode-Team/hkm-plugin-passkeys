<?php

declare(strict_types=1);

use AlfaCode\LetMigrate\Contract\MigrationInterface;
use AlfaCode\LetMigrate\Contract\SchemaBuilderInterface;

/**
 * Passkeys — `passkey_credentials`.
 *
 * Lives in the SIGN-IN database, following `auth_sessions`: on a tenant host
 * that is the tenant's database (from database/tenant-template/, which carries
 * an identical copy of this file), and on a host resolving no tenant it is the
 * central one. A credential is a sign-in artefact, so it belongs wherever the
 * sign-in it serves is recorded.
 *
 * THE UNIQUE INDEX IS ON A HASH, NOT ON THE CREDENTIAL ID.
 * A credential id may be up to 1023 bytes, which base64url-encodes to about
 * 1364 characters — past MySQL's index limit for a utf8mb4 column, and past the
 * point any engine indexes it well. Real ids are 16 to 64 bytes, so a short
 * column would work almost always; the failure would arrive from one unusual
 * authenticator, in production, as a truncated id matching the wrong row.
 *
 * Skips when the table already exists.
 */
return new class implements MigrationInterface {
    public function up(SchemaBuilderInterface $schema): void
    {
        if ($schema->hasTable('passkey_credentials')) {
            return;
        }

        $schema->create('passkey_credentials', static function ($t) {
            $t->id();
            $t->char('user_id', 31)
                ->comment('Soft ref to central users.user_id (ULID) — no cross-DB FK');

            $t->text('credential_id')
                ->comment('base64url, up to ~1364 chars — not indexed; see credential_hash');
            $t->char('credential_hash', 64)
                ->comment('SHA-256 of credential_id — fixed width, so it can be unique-indexed');

            $t->integer('algorithm')->comment('COSE identifier: -7 ES256, -8 EdDSA, -257 RS256');
            $t->text('public_key')
                ->comment('base64 of the DER SubjectPublicKeyInfo — text, not blob, for driver portability');
            $t->string('ed25519_public_key', 128)->nullable()
                ->comment('base64 of the raw Ed25519 key; null for the OpenSSL-verified algorithms');

            $t->bigInteger('sign_count')->unsigned()->default(0)
                ->comment('Clone check: must advance, unless the authenticator reports 0 (every synced passkey)');

            $t->string('label', 100)->comment('What the user calls this key');
            $t->string('aaguid', 32)->nullable()->comment('Authenticator model, hex; all zeros on platform keys');
            $t->boolean('backup_eligible')->default(false)
                ->comment('False = device-bound: lost with the device');

            $t->timestamp('last_used_at')->nullable();
            $t->timestamp('created_at')->default('CURRENT_TIMESTAMP');

            // Globally unique, NOT per user. An authentication has no user to
            // scope the lookup by — that is what makes a usernameless sign-in
            // possible — so two accounts holding one id would make the lookup
            // ambiguous at the moment it decides who is signing in.
            $t->unique(['credential_hash'], 'uniq_passkey_credential');
            $t->index(['user_id'], 'idx_passkey_user');

            $t->engine('InnoDB');
            $t->charset('utf8mb4');
            $t->rowFormat('DYNAMIC');
        });
    }

    public function down(SchemaBuilderInterface $schema): void
    {
        $schema->dropIfExists('passkey_credentials');
    }
};
