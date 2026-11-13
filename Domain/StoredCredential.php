<?php

declare(strict_types=1);

namespace Plugins\Passkeys\Domain;

/**
 * A credential as it lives in storage.
 *
 * `signCount` is on this object rather than fetched separately because the
 * clone check needs the PREVIOUS value and the authentication path needs the
 * key — one read, one record, no chance of verifying against one credential's
 * key while comparing another's counter.
 */
final readonly class StoredCredential
{
    public function __construct(
        /** base64url — the public identifier the browser sends back. */
        public string $credentialId,
        public string $userId,
        public CoseAlgorithm $algorithm,
        public string $publicKeyDer,
        public string $ed25519PublicKey,
        public int $signCount,
        /** What the user calls this key: "MacBook", "YubiKey". Their text. */
        public string $label,
        public string $aaguid,
        public bool $backupEligible,
        public ?\DateTimeImmutable $lastUsedAt = null,
        public ?\DateTimeImmutable $createdAt = null,
    ) {}

    public function key(): CoseKey
    {
        return CoseKey::fromStored($this->publicKeyDer, $this->algorithm, $this->ed25519PublicKey);
    }

    /**
     * Whether losing the registering device would lose this credential.
     *
     * Worth surfacing to a user before they delete anything: a credential that
     * is not backup-eligible lives on one piece of hardware, so "delete my
     * other keys" can leave an account reachable only from a device that may
     * already be in a drawer.
     */
    public function isDeviceBound(): bool
    {
        return !$this->backupEligible;
    }

    /** @return array<string, mixed> Safe to return to the owning user. */
    public function toArray(): array
    {
        return [
            'id'            => $this->credentialId,
            'label'         => $this->label,
            'algorithm'     => $this->algorithm->label(),
            'deviceBound'   => $this->isDeviceBound(),
            'aaguid'        => $this->aaguid,
            'lastUsedAt'    => $this->lastUsedAt?->format(\DateTimeInterface::RFC3339),
            'createdAt'     => $this->createdAt?->format(\DateTimeInterface::RFC3339),
        ];
    }
}
