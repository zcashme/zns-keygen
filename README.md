# zns-keygen

`zns-keygen` is the one-shot genesis custody tool for ZNS.

It must be run once inside the chosen AMD SEV-SNP instance. It creates the ZNS
issuer seed, seals it to that specific instance, writes a binary capsule, emits
a public custody manifest, and exits. It does not expose a socket, does not
sign messages, and does not support migration.

## Role in the ZNS custody architecture

ZNS custody is split across two components that run inside the same measured
SEV-SNP guest:

| Component   | Responsibility                                      | Seed access       |
|-------------|----------------------------------------------------|-------------------|
| `zns-keygen`| Create the seed once, seal it, emit a manifest.     | Create-only, then exit. |
| `zns-mint`  | Unseal the capsule at boot, use the seed to mint.   | Use-only.         |

`zns-keygen` exists so that `zns-mint` never has to contain seed-creation
logic. The mint only ever consumes a capsule that `zns-keygen` produced.

## Operation

When executed, `zns-keygen`:

1. Refuses to run if `zns_seed.capsule`, `zns_custody_manifest.toml`,
   `zns_mint.conf`, or `zns_attestation.bin` already exists.
2. Generates a fresh 32-byte seed using `RDSEED`.
3. Computes the ZIP-32 seed fingerprint locally:
   `BLAKE2b-256(personal="Zcash_HD_Seed_FP", [seed_len] || seed)`, displayed as
   Bech32m with HRP `zip32seedfp`.
4. Temporarily derives only the Treasury transparent funding address and the
   external public key needed to identify the funding UTXO.
5. Derives an SEV-SNP sealing key rooted in the AMD platform's SNP key
   hierarchy, bound to guest policy and measurement.
6. Immediately encrypts the seed with `XChaCha20Poly1305`, binding the capsule
   magic and seed fingerprint into the AAD (Additional Authenticated Data).
7. Persists `zns_seed.capsule` (postcard-serialized struct: magic + fingerprint
   + nonce + ciphertext+tag) and drops the plaintext seed and any derived
   private spending-key material.
8. Displays the Treasury transparent funding address and waits for funding
   through Zebra. The seed does not remain in plaintext memory during this
   operator-controlled wait.
9. Once sufficient funding is detected, derives the SEV-SNP sealing key again,
   decrypts the capsule, verifies the seed fingerprint, derives the Treasury
   and Registry spending keys, builds and signs the genesis anchor transaction,
   broadcasts it through Zebra, and drops the plaintext seed and private key
   material again.
10. Writes `zns_custody_manifest.toml`, `zns_mint.conf`, and
    `zns_attestation.bin`, then exits.

The ordering is:

`generate seed → derive public funding information → immediately seal seed → discard plaintext → wait for funding → temporarily unseal to sign the genesis transaction → discard plaintext again`

The capsule is the authoritative copy of the ceremony seed the moment it is
durably written, which is before the funding wait. There is no resume path.
If the process dies after that write and before the anchor transaction is
broadcast, restarting is refused because the capsule already exists. Deleting
the capsule and re-running generates a different seed and abandons the sealed
one; that is not recovery. Migration and recovery policy are out of scope.

Defaults:

```text
capsule:      zns_seed.capsule
manifest:     zns_custody_manifest.toml
mint_config:  zns_mint.conf
```

## Capsule format

The capsule is a [postcard](https://docs.rs/postcard)-serialized `SeedCapsule`
struct. Postcard writes fixed arrays raw and length-prefixes each `Vec` with
a varint. For the lengths used here those varints are a single byte:

| Offset | Field        | Encoding                         | Description |
|--------|--------------|----------------------------------|-------------|
| 0      | magic        | 8 raw bytes                      | `ZNS_SEED` |
| 8      | fingerprint  | 32 raw bytes                     | ZIP-32 seed fingerprint (plaintext) |
| 40     | nonce        | `0x18` then 24 bytes             | XChaCha20Poly1305 nonce |
| 65     | ciphertext   | `0x30` then 48 bytes             | 32-byte seed + 16-byte Poly1305 tag |

The fingerprint is stored in plaintext so that `zns-mint` can identify which
capsule it has without decrypting. It is not secret; the seed fingerprint is
also published in the manifest.

## Mint config

`zns_mint.conf` is a TOML file written by `zns-keygen` containing:

```toml
network = "mainnet"
expected_seed_fingerprint = "zip32seedfp..."
birthday = 1234567
```

`birthday` is the chain tip height observed after the genesis anchor
transaction is broadcast.

`zns-mint` reads this on startup and refuses to run if the decrypted seed's
fingerprint does not match `expected_seed_fingerprint`.

## AAD and context binding

The encryption binds the following into the AAD so that tampering with the
capsule or swapping ciphertext between capsules is detected:

- The capsule magic (`ZNS_SEED`).
- The seed fingerprint.

The encryption key is an SEV-SNP derived sealing key rooted in the AMD
platform's SNP key hierarchy. The guest does not receive the VCEK private key.
Derivation selects guest policy and measurement. A different CPU, guest
policy, or launch measurement cannot recreate the key, so a capsule sealed in
one guest cannot be decrypted in another.

## Custody Manifest

The manifest is public. It records the seed fingerprint, capsule hash, account
allocation, capsule format, sealing policy, and attestation metadata. It never
contains the seed.

The current account allocation is:

```text
treasury_account: 0
registry_account: 1
```

The manifest also includes the actual SEV-SNP launch parameters extracted from
the attestation report:

- `guest_policy` — the guest policy value (hex)
- `measurement` — the launch measurement (hex)

Sealing derivation selects only those two fields (`guest_policy,measurement`).
Image ID and family ID are not mixed into the sealing key.

The measurement commits to the measured guest launch state. It is not, by
itself, a hash of the `zns-keygen` binary. The deployment and build process
separately ensures that the approved binary is incorporated into that measured
state.

## Attestation

`zns-keygen` requests a SEV-SNP attestation report from the AMD PSP and writes
it to `zns_attestation.bin`. The report is sanity-checked before writing:
`report_data` is compared with `BLAKE2b-512(seed_fingerprint || capsule_hash)`,
and the measurement must not be all zeros. This does not verify the AMD VCEK
signature or certificate chain.

The report signature algorithm is ECDSA P-384 / SHA-384.

The attestation report and custody manifest are written with mode `0644`
(world-readable) so third-party verification tools can read them without
root. The capsule and mint config are written with mode `0600` (owner only).

## Entropy

Seed material and the encryption nonce are both generated using the x86_64
`RDSEED` CPU instruction with a bounded spin loop (up to 10,000 retries per
64-bit word, yielding to the scheduler every 1,000 retries). `RDSEED` draws
directly from the CPU's hardware entropy source. Degenerate outputs (all
zeros or all 0xFF) are rejected.

## Security Boundary

### What this protects against

- **Host/hypervisor reading the capsule offline.** The sealing key is an
  SEV-SNP derived key rooted in the AMD platform's SNP key hierarchy, bound to
  guest policy and measurement. A different CPU, a different guest policy, or
  a different measurement cannot recreate the key and cannot decrypt the
  capsule. The guest does not receive the VCEK private key.
- **Capsule tampering.** The Poly1305 authentication tag fails decryption if
  the ciphertext, nonce, or AAD are modified.
- **Ciphertext reuse across contexts.** The AAD binds the capsule magic and
  seed fingerprint, so a capsule cannot be replayed with a different
  fingerprint. Platform binding comes from the SEV-SNP derived key, which is
  unique per physical CPU and selected guest fields.
- **Plaintext seed during the funding wait.** The seed is sealed and dropped
  before `zns-keygen` waits for the operator's funding transaction. Spending
  keys are derived again only after funding arrives, and dropped again after
  the anchor transaction is broadcast.
- **Accidental re-run.** `zns-keygen` refuses to overwrite an existing capsule
  or manifest.

### What this does NOT protect against

- **Root/admin inside the guest.** SEV-SNP protects the guest from the host,
  not from itself. Any process with access to `/dev/sev-guest` inside the same
  measured guest can re-derive the same sealing key and decrypt the capsule.
  **SEV-SNP sealing is guest-bound, not process-bound.**
- **Modified guest software.** If an attacker boots a different image that
  still has access to the SEV-SNP derived-key interface, they can request the
  same key. The measurement binding mitigates this only if the capsule is
  sealed to a measurement that the attacker's image does not match.
- **Memory inspection after decrypt.** Once `zns-mint` decrypts the seed into
  process memory, guest root can read it via `/proc/$pid/mem`, ptrace, core
  dumps, or by replacing the mint binary itself.

### Threat model summary

The current design gives:

> Only code inside a compatible measured SEV-SNP guest can decrypt the
> capsule.

It does **not** give:

> Only `zns-mint` can decrypt the capsule.

Achieving process-bound secrecy requires a stronger boundary than ordinary
Linux userspace — for example a VMPL/SVSM seed authority, an attestation-gated
key release, or an external HSM/MPC signer. These are future work.

### Liveness

This intentionally accepts liveness risk: there is no migration path in v1. If
the chosen SEV-SNP instance is lost, the v1 capsule is lost and the seed is
unrecoverable.
