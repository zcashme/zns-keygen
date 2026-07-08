# zns-keys

`zns-keys` is the key-custody component for ZNS. It replaces the old one-shot
`zns-keygen` model with a long-running signer boundary:

```text
zns-mint -> zns-keys -> signature
```

`zns-mint` never loads the seed. `zns-keys` creates it, seals it for restart,
unseals it inside the SEV-SNP VM, and exposes a tiny local signing API.

## Commands

```text
zns-keys init [--state PATH] [--report PATH] [--challenge-hex HEX64]
zns-keys status [--state PATH]
zns-keys attest [--state PATH] [--report PATH] [--challenge-hex HEX64]
zns-keys verify [--state PATH] [--report PATH] [--challenge-hex HEX64]
zns-keys serve [--state PATH] [--socket PATH]
```

Defaults:

```text
state:  zns_keys.state
report: zns_attestation.report
socket: zns-keys.sock
```

## Lifecycle

1. `init` generates a 32-byte seed using `RDSEED`.
2. It computes the ZIP-32 seed fingerprint.
3. It requests an AMD SEV-SNP attestation report binding:
   - `report_data[0..32] = seed fingerprint`
   - `report_data[32..64] = optional verifier challenge`
4. It seals the seed with a SEV-SNP derived key and writes `zns_keys.state`.
5. `serve` unseals the seed and listens on a Unix socket for `zns-mint`.

## Socket Protocol

The v1 RPC surface is line-oriented and dependency-free:

```text
status
sign <hex-message>
```

Responses are one line:

```text
OK fingerprint <bech32-fingerprint>
ERR <message>
```

Orchard/Pallas signing is not wired yet. The `sign` command currently returns a
clear error. The signer boundary and sealed custody lifecycle are in place so
`zns-mint` can be migrated to call `zns-keys` before the Orchard implementation
is added.

## Migration

`migrate-export` and `migrate-import` are intentionally reserved for v2. The
intended design is signer-to-signer migration:

1. New `zns-keys` instance creates an attested migration public key.
2. Old `zns-keys` verifies the new attestation.
3. Old `zns-keys` encrypts the seed to the new instance.
4. New `zns-keys` decrypts inside its TEE and seals locally.

No plaintext seed should pass through the operator.

## Security Boundary

This protects the seed from disk/offline theft and from the cloud host when run
inside a genuine SEV-SNP VM. On managed GCP SEV-SNP, in-guest root is not
cryptographically blocked from inspecting guest memory or calling
`SNP_GET_DERIVED_KEY`. The public claim must be scoped accordingly.
