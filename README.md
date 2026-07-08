# ZNS Keygen Ceremony

`zns-keygen` is a secure, attested key generation ceremony for Zcash Name Service (ZNS).

It operates entirely within an AMD SEV-SNP Trusted Execution Environment (TEE) to generate, attest, and securely seal a Zcash master seed, guaranteeing that the seed is never exposed to a human or the host operating system.

## Ceremony Flow

1. **Hardware Entropy:** Harvests true random numbers directly from the AMD silicon via `RDSEED`.
2. **Cryptographic Proof:** Commits to the seed using a one-way `Blake2b-256` hash (ZIP-32 fingerprint format) and asks the AMD Secure Processor to embed this fingerprint into a signed Attestation Report.
3. **Hardware Sealing:** Derives a VM-specific encryption key directly from the hardware measurement, and seals the plaintext seed using `ChaCha20-Poly1305`.
4. **Zeroization:** Wipes all traces of the plaintext seed and hardware key from volatile memory using compiler-safe primitives.

## Artifacts

The ceremony outputs two files to the local directory:
* `zns_attestation.report`: The AMD SEV-SNP Attestation Report (verifiable by a remote party).
* `sealed_seed.bin`: The 60-byte encrypted payload containing the seed, which can only be decrypted by the exact same TEE environment.

## Security

This binary is designed with a strict fail-closed philosophy. It will abort immediately if it detects a missing TEE device, firmware errors, or exhaustion of hardware entropy. See `audit.md` for a list of ongoing architectural security enhancements.
