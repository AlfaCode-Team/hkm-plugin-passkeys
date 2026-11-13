<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Infrastructure\Persistence;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\RepositoryException;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\DatabasePort;
use Plugins\Passkeys\API\Contracts\PasskeyStoreContract;
use Plugins\Passkeys\Domain\CoseAlgorithm;
use Plugins\Passkeys\Domain\RegistrationResult;
use Plugins\Passkeys\Domain\StoredCredential;

/**
 * Credentials in `passkey_credentials`.
 *
 * TWO STORAGE DECISIONS THAT ARE NOT OBVIOUS
 * ------------------------------------------
 * **The unique index is on a HASH of the credential id, not the id.** A
 * credential id may be up to 1023 bytes, which base64url-encodes to about 1364
 * characters — past MySQL's 3072-byte index limit once a utf8mb4 column is
 * accounted for, and past the point where any engine indexes it efficiently.
 * Real ids are 16 to 64 bytes, so a short column would work almost always,
 * which is the worst kind of almost: the failure arrives from one unusual
 * authenticator, in production, as a truncated id that then matches the wrong
 * row. A `char(64)` sha256 is fixed-width, portable and collision-free in any
 * sense that matters here.
 *
 * **The public key is stored base64-encoded in a text column.** It is binary
 * DER, and a `blob` would be the natural home — but binary columns are the one
 * place MySQL, PostgreSQL and SQLite disagree most through PDO, with silent
 * charset mangling as the failure. The cost is 33% more bytes for a value a few
 * hundred bytes long; the benefit is that the same migration and the same
 * repository work on all three drivers, which this plugin cannot otherwise
 * promise.
 *
 * Every `\PDOException` is translated, per the repository rules: no vendor
 * exception escapes this layer.
 */
final class DatabasePasskeyStore implements PasskeyStoreContract
{
    private const TABLE = 'passkey_credentials';

    /**
     * Named rather than `*`, which is not only style.
     *
     * `SELECT *` ties the hydrator to the table's current shape: a column added
     * later by a migration — or by a deployment that extended the table —
     * arrives in every row of every read for no reason, and `credential_id` is
     * already up to 1364 characters. Naming the columns also means this read
     * keeps working unchanged when one is added, instead of silently getting
     * wider.
     */
    private const COLUMNS = 'user_id, credential_id, algorithm, public_key, ed25519_public_key, '
        . 'sign_count, label, aaguid, backup_eligible, last_used_at, created_at';

    public function __construct(private readonly DatabasePort $db) {}

    public function findByCredentialId(string $credentialId): ?StoredCredential
    {
        try {
            $row = $this->db->queryOne(
                'SELECT ' . self::COLUMNS . ' FROM ' . self::TABLE
                . ' WHERE credential_hash = :hash LIMIT 1',
                ['hash' => self::hash($credentialId)],
            );
        } catch (\PDOException $e) {
            throw new RepositoryException(
                'Failed to look up a passkey credential.',
                layer: 'repository.passkeys',
                previous: $e,
            );
        }

        return $row === null ? null : self::hydrate($row);
    }

    public function allForUser(string $userId): array
    {
        try {
            $rows = $this->db->query(
                'SELECT ' . self::COLUMNS . ' FROM ' . self::TABLE
                . ' WHERE user_id = :user ORDER BY created_at ASC',
                ['user' => $userId],
            );
        } catch (\PDOException $e) {
            throw new RepositoryException(
                "Failed to list passkeys for user [{$userId}].",
                layer: 'repository.passkeys',
                context: ['userId' => $userId],
                previous: $e,
            );
        }

        $credentials = [];

        foreach ($rows as $row) {
            if (\is_array($row)) {
                $credentials[] = self::hydrate($row);
            }
        }

        return $credentials;
    }

    public function save(string $userId, RegistrationResult $result, string $label): StoredCredential
    {
        $now = new \DateTimeImmutable();

        try {
            $this->db->execute(
                'INSERT INTO ' . self::TABLE . ' (
                    user_id, credential_id, credential_hash, algorithm, public_key, ed25519_public_key,
                    sign_count, label, aaguid, backup_eligible, created_at
                 ) VALUES (
                    :user, :credential_id, :hash, :algorithm, :public_key, :ed25519,
                    :sign_count, :label, :aaguid, :backup_eligible, :created_at
                 )',
                [
                    'user'            => $userId,
                    'credential_id'   => $result->credentialId,
                    'hash'            => self::hash($result->credentialId),
                    'algorithm'       => $result->algorithm->value,
                    'public_key'      => base64_encode($result->publicKeyDer),
                    'ed25519'         => $result->ed25519PublicKey === ''
                        ? null
                        : base64_encode($result->ed25519PublicKey),
                    'sign_count'      => $result->signCount,
                    'label'           => mb_substr($label, 0, 100),
                    'aaguid'          => $result->aaguid,
                    'backup_eligible' => $result->backupEligible ? 1 : 0,
                    'created_at'      => $now->format('Y-m-d H:i:s'),
                ],
            );
        } catch (\PDOException $e) {
            throw new RepositoryException(
                'Failed to store a passkey credential.',
                layer: 'repository.passkeys',
                context: ['userId' => $userId],
                previous: $e,
            );
        }

        return new StoredCredential(
            credentialId: $result->credentialId,
            userId: $userId,
            algorithm: $result->algorithm,
            publicKeyDer: $result->publicKeyDer,
            ed25519PublicKey: $result->ed25519PublicKey,
            signCount: $result->signCount,
            label: $label,
            aaguid: $result->aaguid,
            backupEligible: $result->backupEligible,
            createdAt: $now,
        );
    }

    public function recordUse(string $credentialId, int $signCount, \DateTimeImmutable $at): void
    {
        try {
            $this->db->execute(
                'UPDATE ' . self::TABLE
                . ' SET sign_count = :count, last_used_at = :at WHERE credential_hash = :hash',
                [
                    'count' => $signCount,
                    'at'    => $at->format('Y-m-d H:i:s'),
                    'hash'  => self::hash($credentialId),
                ],
            );
        } catch (\PDOException $e) {
            // Translated and rethrown rather than swallowed. Losing this write
            // disables the clone check for this credential from here on, and a
            // silently skipped security check is worse than a failed sign-in
            // the user can retry.
            throw new RepositoryException(
                'Failed to record passkey use.',
                layer: 'repository.passkeys',
                previous: $e,
            );
        }
    }

    public function delete(string $userId, string $credentialId): bool
    {
        try {
            // Scoped by user_id as well as by the credential, so an
            // authenticated user cannot delete another account's credential by
            // supplying its id.
            $affected = $this->db->execute(
                'DELETE FROM ' . self::TABLE . ' WHERE user_id = :user AND credential_hash = :hash',
                ['user' => $userId, 'hash' => self::hash($credentialId)],
            );
        } catch (\PDOException $e) {
            throw new RepositoryException(
                'Failed to delete a passkey credential.',
                layer: 'repository.passkeys',
                context: ['userId' => $userId],
                previous: $e,
            );
        }

        return $affected > 0;
    }

    /** sha256 hex of the base64url id — fixed width, so it can be indexed. */
    private static function hash(string $credentialId): string
    {
        return hash('sha256', $credentialId);
    }

    /** @param array<string, mixed> $row */
    private static function hydrate(array $row): StoredCredential
    {
        $ed25519 = $row['ed25519_public_key'] ?? null;

        return new StoredCredential(
            credentialId: (string) ($row['credential_id'] ?? ''),
            userId: (string) ($row['user_id'] ?? ''),
            algorithm: CoseAlgorithm::fromIdentifier((int) ($row['algorithm'] ?? 0)),
            publicKeyDer: self::key((string) ($row['public_key'] ?? ''), 'public_key'),
            ed25519PublicKey: \is_string($ed25519) && $ed25519 !== ''
                ? self::key($ed25519, 'ed25519_public_key')
                : '',
            signCount: (int) ($row['sign_count'] ?? 0),
            label: (string) ($row['label'] ?? ''),
            aaguid: (string) ($row['aaguid'] ?? ''),
            // Compared loosely on purpose: MySQL returns tinyint as '1'/'0',
            // PostgreSQL returns a PHP bool, SQLite an int. A strict `=== 1`
            // would read as false on two of the three.
            backupEligible: (bool) ($row['backup_eligible'] ?? false),
            lastUsedAt: self::time($row['last_used_at'] ?? null),
            createdAt: self::time($row['created_at'] ?? null),
        );
    }

    /**
     * A stored key, decoded, or a refusal naming the column.
     *
     * `(string) base64_decode($v, true)` casts the `false` of a corrupt column
     * to `''` — which is not an error anywhere, so the credential hydrates, the
     * ceremony runs, OpenSSL declines to load a zero-byte key, and `verify()`
     * returns false. The user is told their passkey did not verify and the log
     * records a signature failure, for a row that is simply damaged. A
     * repository is the layer that is supposed to notice that, so it does.
     */
    private static function key(string $encoded, string $column): string
    {
        $decoded = base64_decode($encoded, true);

        if ($decoded === false || $decoded === '') {
            throw new RepositoryException(
                "The stored passkey column [{$column}] is not valid base64, so the credential cannot be read.",
                layer: 'repository.passkeys',
                context: ['column' => $column],
            );
        }

        return $decoded;
    }

    private static function time(mixed $value): ?\DateTimeImmutable
    {
        if (!\is_string($value) || $value === '') {
            return null;
        }

        try {
            return new \DateTimeImmutable($value);
        } catch (\Exception) {
            // A timestamp this cannot read must not stop a sign-in: it is
            // display metadata, and the credential is still valid.
            return null;
        }
    }
}
