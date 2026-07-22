# Plane-PH artifact backup-key custody

## Security boundary

The artifact vault no longer derives the operator-backup archive-encryption key
from the vault master. `createArtifactVault()` requires a private branded
`backupKeyCustody` capability enrolled for the exact vault ID, immutable vault
slot, session-nucleus hash, custody identity, and custody epoch. The constructor
for that capability is exposed only from the artifact vault's operator surface.
The main and worker surfaces expose neither the constructor nor its callbacks.

The vault sends archive plaintext to the custody port for sealing and receives a
closed external-custody envelope. The envelope binds:

- vault ID, vault slot, and session nucleus;
- random backup and seal-effect references;
- custody identity and epoch;
- the digest of the exact serialized backup;
- the digest of a sorted `(artifact_handle, record_digest)` inventory; and
- the external format, ciphertext digest, and opaque seal reference.

No raw archive key is accepted or returned by this contract. Before open, the
vault exact-reads the current external archive state and compares all immutable
bindings. It repeats that read after open so a concurrent revocation cannot
silently yield accepted plaintext. Cross-vault, cross-epoch, revoked, replayed,
or modified envelopes fail closed.

Callback results are synchronous, closed data. Proxies, Promises, own or
inherited thenables, accessors, and unexpected fields are rejected. If an open
callback returns a plaintext `Buffer` inside a malformed object or function, the
vault captures that own data property before wrapper validation and zeroizes the
original buffer on every rejection path.

## Durable seal intent and archive registry

Before the first external seal effect, the vault writes the exact serialized
backup into the private `backup-intents/` staging directory under a dedicated
AEAD key. It then commits a `prepared` intent to the externally anchored vault
index. The intent fixes the backup digest, artifact-inventory digest, backup
reference, seal-effect reference, creation time, and destination descriptor
identity. The staging key is not an external archive key and the staged bytes
never leave the private vault root unencrypted.

Seal publication is a monotonic state machine:

1. encrypted payload staged;
2. `prepared` intent committed to the external index anchor;
3. seal submitted once, or reconciled by the same stable effect reference;
4. exact external seal read back and the intent advanced to `sealed`;
5. the now-unneeded encrypted staging payload removed;
6. the complete outer custody envelope written, fsynced, and read back from the
   same destination descriptor;
7. the index advanced to `published`.

A process loss or temporary readback outage resumes these same identities. It
does not generate a second backup or seal effect. A definitively uncommitted
staging file is removed immediately; startup also removes crash-orphaned staging
files that have no anchored intent. Startup cleanup takes the vault lock and
skips reconciliation when another process already owns it, leaving explicit
stale-lock recovery reachable after a crash. If a prepared staging payload is
missing or corrupt, the vault exact-reads the external custodian: an already
active effect advances to `sealed`, a definitively absent effect discards the
unusable intent, and an unavailable readback fails without guessing. `sealed`
intents never retain the master-derived staging payload. A single pending intent
can be rebound to a new empty destination descriptor after the original inode is
lost, without creating another archive or seal effect. The externally anchored
index, not backup media, owns the lifetime archive registry. Backup snapshots
exclude this registry, and restore merges the current registry rather than
accepting an older copy from media.

Every registry entry contains the exact sorted artifact inventory, including
each artifact's record digest, plus the immutable archive/seal identities. A
single artifact may belong to at most 64 lifetime archives, and admission of a
sixty-fifth member fails before the seal callback. The entire vault registry is
also bounded. Revoked entries remain in the registry as permanent completeness
evidence.

## Monotonic erasure order

Artifact erasure uses this order:

1. The vault derives the complete member set from its independently anchored
   lifetime archive registry.
2. It constructs the exact worst-case terminal receipt and proves that the next
   authenticated deletion ledger fits its configured byte ceiling.
3. It commits a single-flight deletion intent to the external index anchor. The
   intent fixes the prior record digest, reason, requested time, retirement
   effect, member-registry digest, ledger generation, and exact capacity
   projection.
4. The external custody atomically preflights restore fences, retires the
   artifact identity, and destroys every whole-archive key in that exact set.
5. The vault requires set-equal retirement output and exact-reads the retirement
   plus every individual archive revocation. A lost acknowledgement is
   reconciled with the persisted reason, time, and effect; it is never relabeled
   or submitted under a new identity.
6. Only after that evidence is exact does the vault commit the deletion-ledger
   entry that makes the current-store wrapped data key unreachable.
7. The anchored archive states and deletion intent are finalized, and the
   current object ciphertext is unlinked on a best-effort basis.

While a deletion intent is pending, reads of that artifact fail closed, a
different reason is rejected, and another deletion cannot consume its reserved
ledger capacity. If the deletion ledger commits but index cleanup is interrupted,
retry verifies the same external retirement and completes cleanup without a
second retirement effect. Every later deletion-ledger read also compares the
retirement member set against the independent anchored archive registry; an
aggregate `active_archive_count: 0` claim is never sufficient evidence.

Whole-archive revocation is deliberately conservative. Erasing one member makes
the entire old archive unrecoverable, including non-erased members. Operators
must create a new post-erasure backup for the remaining inventory. External
retirement also rejects future sealing attempts that contain a retired artifact.

## Restore fencing and restart reconciliation

Backup verification uses before/after archive-state reads. Restore additionally
uses an external custody fence because a final read alone cannot prevent
retirement from linearizing immediately before the restored index commit.

Before fence acquisition, the vault commits a restore intent to the external
index anchor. It binds the exact source descriptor identity and custody envelope,
stable restore/acquire/release effect references, recovery flags, requested
time, and the preselected restore generation. Restore then:

1. acquires or exact-reconciles that fence;
2. opens and validates the complete backup and every nested ciphertext;
3. prepares and fsyncs the preselected object generation and its parent entry;
4. exact-reads the fence as active immediately before the anchored index commit;
5. commits the restored generation and recovery receipt atomically with the
   restore intent;
6. releases or exact-reconciles the fence using the stable release effect; and
7. advances the intent to a terminal `released` receipt.

The custodian must reject member retirement while any matching restore fence is
active, and it must preflight all matching members before destroying any key.
Fence acquisition loss before commit leaves the prior object generation
selected. A lost acquisition acknowledgement resumes the same active fence after
restart. A lost release acknowledgement after commit resumes the same committed
receipt and never selects a second generation while that committed generation is
physically readable. Terminal released receipts record the exact index generation
at which they completed. They are replayed only while that generation is still
current and every registered ciphertext decrypts and passes integrity checks.
Any later anchored mutation or physical object loss starts a fresh restore with
new restore/effect/generation identities; a stale receipt cannot report recovery
success. A released receipt remains anchored for generation-scoped retries until
a fresh restore of that archive supersedes it, and released entries do not block
ordinary vault mutations.

Deletion receipts distinguish three different claims:

- `current_store_erasure`: the authenticated local deletion ledger committed;
- `external_backup_key_revocation`: all member-archive keys were revoked under
  the whole-archive policy and exact-read back; and
- `backup_media_erasure`: `not_attested`. Key revocation does not prove that a
  disk, tape, copied file, snapshot, or other physical medium was destroyed.

## Current assurance and production gate

The JavaScript custody constructor is an in-process integration boundary for
hostile contract tests. It is hard-coded as `production_ready: false`,
`hil_verified: false`, and `backup_media_erasure_attested: false`. It does not
claim an OS process boundary, HSM, Secure Enclave, TPM, native keychain, backup
appliance integration, or independent media-erasure witness.

Production remains blocked until a separately packaged native or external
custodian implements the same closed synchronous protocol with:

- independently administered key storage and monotonic state;
- crash-durable atomic artifact retirement and member-archive key destruction;
- crash-durable, mutually serialized restore-fence acquisition and release;
- exact readback after process loss and machine restart;
- dedicated operator principal, ACL, signing, and release provenance;
- backup/key recovery drills and destructive-media procedures; and
- signed HIL evidence for sealing, restore, lost acknowledgement, rollback,
  revocation, stale epoch, and physical-media disposition cases.

Passing the in-process package tests proves contract behavior only. It is not
production or HIL evidence.
