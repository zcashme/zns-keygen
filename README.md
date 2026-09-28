# zns-keygen

`zns-keygen` is the one-shot genesis custody tool for ZNS.

It must be run once inside a compatible measured SEV-SNP guest. It creates the
ZNS issuer seed, seals it to the SEV-SNP platform and selected measured guest
context, writes a binary capsule, emits a public custody manifest, and exits.
It does not expose a socket and does not sign messages. It does not support
migration. Migration and recovery are planned future work and remain in scope
for v1. The seed is not permanently bound to one binary and one machine.

## Role in the ZNS custody architecture

ZNS custody is split across two components that run inside the same measured
SEV-SNP guest:

| Component    | Responsibility                                    | Seed access                       |
|--------------|---------------------------------------------------|-----------------------------------|
| `zns-keygen` | Create seed, seal it, sign genesis once.          | Create + one-time use, then exit. |
| `zns-mint`   | Unseal the capsule at boot, use the seed to mint. | Use-only.                         |

`zns-keygen` exists so that `zns-mint` never has to contain seed-creation
logic. The mint only ever consumes a capsule that `zns-keygen` produced.

## Operation

```text
zns-keygen
zns-keygen --help
```

With no arguments, `zns-keygen` runs the ceremony below. `-h` and `--help` print usage and exit. They do not generate a seed, write files, or wait for funding. Any other argument prints the same usage and exits with status 2.

The network is chosen at compile time (`--features testnet` selects testnet). The help text names the network this binary was built for.

When the ceremony runs, `zns-keygen`:

1. Resumes from `keys/ceremony_state.toml` when that file and the capsule are
   both present. If the capsule exists without ceremony state, it refuses and
   leaves the capsule in place. A new ceremony also refuses to start when the
   manifest, mint config, or attestation file already exists.
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
7. Persists `keys/zns_seed.capsule` (postcard-serialized struct: magic + fingerprint
   + nonce + ciphertext+tag), records `SEALED` in `keys/ceremony_state.toml`
   with the Treasury address and public key, and drops the plaintext seed.
8. Requests a SEV-SNP attestation bound to
   `BLAKE2b-512(seed_fingerprint ‖ capsule_hash)`. The VCEK and ASK are fetched
   from AMD KDS and checked against a pinned AMD ARK. The verified report is
   persisted as `keys/zns_attestation.bin`. This happens before funding and
   before any on-chain action. The state then becomes `WAITING_FOR_FUNDS`.
9. Displays the Treasury transparent funding address and waits for funding
   through Zebra. The seed does not remain in plaintext memory during this
   operator-controlled wait. Observed funding is recorded as `FUNDED`.
10. Unseals the capsule, derives the Treasury external index-0 signing key and
    the Treasury and Registry Orchard full viewing keys, builds and signs the
    genesis anchor, and persists that exact transaction as `ANCHOR_BUILT`
    before broadcasting it. The plaintext seed and signing key are dropped
    before the transaction is stored.
11. Asks Zebra whether that txid is already known. If it is not, broadcasts the
    stored transaction. If it is, does not build or broadcast another. Either
    way, immediately persists `ANCHOR_BROADCAST` with the txid and birthday.
12. Writes `keys/zns_custody_manifest.toml` and `keys/zns_mint.conf`, records
    `COMPLETE`, and exits.

The ordering is:

`generate seed → seal capsule → request and verify attestation → persist attestation → wait for funding → unseal → build, sign, and persist the anchor → broadcast → persist txid and birthday → write manifest and mint config → complete`

Restart continues from the persisted state:

- `SEALED` requests and verifies attestation when it is not already stored, then waits for funding.
- `WAITING_FOR_FUNDS` resumes the funding wait.
- `FUNDED` constructs the anchor.
- `ANCHOR_BUILT` checks whether that stored transaction was broadcast before sending it.
- `ANCHOR_BROADCAST` writes the manifest and mint config. Each file is created by a synced rename, and an existing file is accepted only when its bytes match. It does not unseal the seed or submit another transaction.
- `COMPLETE` exits successfully.

The capsule is the authoritative copy of the ceremony seed the moment it is
durably written, which is before attestation and before the funding wait.
Deleting the capsule and re-running generates a different seed and abandons
the sealed one; that is not recovery. A capsule written before ceremony state
existed cannot be resumed. This tool does not implement migration or recovery.
That support is planned future work and remains in scope for v1.

Defaults:

```text
capsule:      keys/zns_seed.capsule
state:        keys/ceremony_state.toml
manifest:     keys/zns_custody_manifest.toml
mint_config:  keys/zns_mint.conf
attestation:  keys/zns_attestation.bin
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

`keys/zns_mint.conf` is a TOML file written by `zns-keygen` containing:

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
Derivation selects guest policy and measurement. The capsule is sealed to the
SEV-SNP platform and that selected measured guest context. A different CPU,
guest policy, or launch measurement cannot recreate the key.

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
it to `keys/zns_attestation.bin` after the capsule is sealed and before it
waits for funding. The report is the VCEK-signed evidence. The VCEK, and the
ASK that certifies it, are fetched from AMD's Key Distribution Service
(`kdsintf.amd.com`). The guest does not depend on the host certificate table.
Before writing, it verifies the report:

- The report's signing-key field says VCEK. A VLEK, or a masked signature, is rejected.
- The ASK fetched from AMD verifies under a pinned AMD ARK for Milan, Genoa, or Turin. The ARK bytes served by KDS are not the trust anchor.
- That ASK signs the VCEK, and the VCEK's ECDSA P-384 / SHA-384 signature covers the report.
- `report_data` matches `BLAKE2b-512(seed_fingerprint || capsule_hash)`, and the measurement is not all zeros.

A later resume reads `keys/zns_attestation.bin` and repeats that check: it fetches the VCEK and ASK again, verifies the signature, and only then copies the measurement and guest policy into the custody manifest.

The AMD PSP records the launch measurement in the report. A verifier outside the guest, the host or anyone reading `keys/zns_attestation.bin`, compares that value to the built image.

The report signature algorithm is ECDSA P-384 / SHA-384.

The attestation report and custody manifest are written with mode `0644`
(world-readable) so third-party verification tools can read them without
root. The capsule, ceremony state, and mint config are written with mode
`0600` (owner only). Ceremony state holds the Treasury address and, once the
anchor exists, the signed transaction, txid, and birthday.

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
  before `zns-keygen` waits for the operator's funding transaction. After
  funding, the Treasury account private key is dropped as soon as the external
  index-0 signing key is derived. That signing key is erased after it signs,
  and the anchor material is dropped before the transaction is serialized.
  Upstream Treasury account and Orchard spending-key types do not support
  in-place zeroization; their lifetimes are therefore minimized to the
  derivation scope, but dropped copies may leave residual bytes in guest
  memory until that memory is reused or the VM is destroyed.
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
- **Memory inspection after decrypt.** Once either `zns-keygen` or `zns-mint`
  decrypts the seed into process memory, guest root can inspect it during that
  live window via `/proc/$pid/mem`, ptrace, core dumps, or by replacing the
  binary itself.

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

This tool has no migration path. If the current SEV-SNP platform or measured
guest context is lost, the capsule cannot be unsealed until migration and
recovery exist. Those are planned v1 work, because the seed cannot be
permanently bound to one binary and one machine.
