# zns-keys

`zns-keys` is the key-custody component for ZNS. It replaces the old one-shot
`zns-keygen` model with a long-running signer boundary:

```text
zns-mint -> zns-keys -> signature
```

`zns-mint` never loads the seed. `zns-keys` creates it, seals it for restart,
unseals it inside the SEV-SNP VM, and exposes a tiny local signing API.

## Operation

When executed, `zns-keys` will automatically:

1. Check for an existing `zns_seed.sealed` file.
2. If none exists, it generates a new 32-byte seed using `RDSEED`, computes the ZIP-32 seed fingerprint, seals it with a SEV-SNP derived key, and writes `zns_seed.sealed`.
3. Unseal the seed and listen on a Unix socket for `zns-mint`.

Defaults:

```text
seed file: zns_seed.sealed
socket:    zns-keys.sock
```

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

1. New `zns-keys` instance creates a migration public key.
2. Old `zns-keys` encrypts the seed to the new instance.
3. New `zns-keys` decrypts inside its TEE and seals locally.

No plaintext seed should pass through the operator.

## Security Boundary

This protects the seed from disk/offline theft and from the cloud host when run
inside a genuine SEV-SNP VM. On managed GCP SEV-SNP, in-guest root is not
cryptographically blocked from inspecting guest memory or calling
`SNP_GET_DERIVED_KEY`. The public claim must be scoped accordingly.
