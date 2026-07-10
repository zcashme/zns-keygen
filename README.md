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

1. Refuses to run if `zns_seed.capsule`, `zns_custody_manifest.toml`, or
   `zns_mint.conf` already exists.
2. Generates a fresh 32-byte seed using `RDSEED`.
3. Computes the ZIP-32 seed fingerprint locally:
   `BLAKE2b-256(personal="Zcash_HD_Seed_FP", [seed_len] || seed)`, displayed as
   Bech32m with HRP `zip32seedfp`.
4. Derives an instance-bound SEV-SNP VMRK sealing key using guest policy, image
   ID, family ID, and measurement.
5. Encrypts the seed with `XChaCha20Poly1305`, binding the capsule magic
   and seed fingerprint into the AAD (Additional Authenticated Data).
6. Writes `zns_seed.capsule` (postcard-serialized struct: magic + fingerprint + nonce + ciphertext+tag).
7. Writes `zns_custody_manifest.toml` (public metadata, TOML format).
8. Writes `zns_mint.conf` (mint config with expected seed fingerprint, TOML format).
9. Exits.

Defaults:

```text
capsule:      zns_seed.capsule
manifest:     zns_custody_manifest.toml
mint_config:  zns_mint.conf
```

## Capsule format

The capsule is a bincode-serialized `SeedCapsule` struct containing:

| Field        | Length | Description                                  |
|--------------|--------|----------------------------------------------|
| magic        | 8      | `ZNSCAPS1`                                   |
| fingerprint  | 32     | ZIP-32 seed fingerprint (plaintext, for quick identification) |
| nonce        | 24     | XChaCha20Poly1305 nonce (random, stored in plaintext) |
| ciphertext   | 48     | 32-byte seed encrypted + 16-byte Poly1305 auth tag |

The fingerprint is stored in plaintext so that `zns-mint` can identify which
capsule it has without decrypting. It is not secret; the seed fingerprint is
also published in the manifest.

## Mint config

`zns_mint.conf` is a TOML file written by `zns-keygen` containing:

```toml
network = "mainnet"
expected_seed_fingerprint = "zip32seedfp..."
```

`zns-mint` reads this on startup and refuses to run if the decrypted seed's
fingerprint does not match `expected_seed_fingerprint`. This file must be part
of the measured launch state.

## AAD and context binding

The encryption binds the following into the AAD so that tampering with the
capsule or swapping ciphertext between capsules is detected:

- The capsule magic (`ZNSCAPS1`).
- The seed fingerprint.

Network and sealing-policy binding are enforced by the SEV-SNP key derivation
itself: different VM launches get different VMRK-derived sealing keys, so a
capsule sealed on one VM cannot be decrypted on another.

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
- `image_id` — the image ID set at launch (hex)
- `family_id` — the family ID set at launch (hex)
- `measurement` — the VM launch measurement / code hash (hex)

These let a verifier reproduce the sealing key derivation parameters without
parsing the raw attestation report.

## Attestation

`zns-keygen` requests a SEV-SNP attestation report from the AMD PSP and writes
it to `zns_attestation.bin`. The report is self-verified before writing: the
`report_data` field inside the report is checked against
`BLAKE2b-512(seed_fingerprint || capsule_hash)` to ensure the PSP embedded
the correct binding.

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

- **Host/hypervisor reading the capsule offline.** The sealing key is derived
  from the AMD SEV-SNP VMRK and guest fields. A different VM, a different
  launch, or a different measurement cannot recreate the key and cannot
  decrypt the capsule.
- **Capsule tampering.** The Poly1305 authentication tag fails decryption if
  the ciphertext, nonce, or AAD are modified.
- **Ciphertext reuse across contexts.** The AAD binds the capsule magic and
  seed fingerprint, so a capsule cannot be replayed with different ciphertext.
  Network binding is enforced by the SEV-SNP VMRK, which is unique per VM launch.
- **Accidental re-run.** `zns-keygen` refuses to overwrite an existing capsule
  or manifest.

### What this does NOT protect against

- **Root/admin inside the guest.** SEV-SNP protects the guest from the host,
  not from itself. Any process with access to `/dev/sev-guest` inside the same
  measured guest can re-derive the same sealing key and decrypt the capsule.
  SEV-SNP sealing provides **VM-bound secrecy, not process-bound secrecy**.
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
