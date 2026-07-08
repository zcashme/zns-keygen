# Security Audit Roadmap (zns-keygen)

The following design-level security vulnerabilities were identified in the architecture of the ceremony and must be addressed.

## 1. Host-Biased Entropy (E2)
**Problem:** The master seed is 100% sourced from `RDSEED`, which is serviced by the host hypervisor. A malicious host can bias or starve this to force a predictable key.
**Fix:** Cryptographically mix `RDSEED` with OS-level entropy (via `rand::rngs::OsRng`) and an authenticated user challenge/salt using a Key Derivation Function (HKDF).

## 2. In-Guest Key Reuse (E1/E10)
**Problem:** The hardware key we derive is identical for any VMPL0 process running in the same VM image. A compromised co-tenant could request the same key and decrypt our `sealed_seed.bin`.
**Fix:** Update the `GuestFieldSelect` bitfield to include the `launch_id` and `policy` bits. Use the hardware key as an input to HKDF (along with our generated nonce) to derive a unique, per-ceremony sealing key (`K_cer`).

## 3. Cryptographic Binding via AAD (E12)
**Problem:** The ChaCha20-Poly1305 encryption doesn't cryptographically bind the ciphertext to the attestation report. An attacker could swap artifacts around.
**Fix:** Pass the 32-byte `SeedFingerprint` (or the whole `report_data`) into the `.encrypt()` method as Additional Authenticated Data (AAD).

## 4. No Report Freshness (E5)
**Problem:** The attestation report doesn't include a challenge (nonce) from the verifier. Because it's static, an attacker can capture the report and sealed seed, and replay them to verifiers indefinitely.
**Fix:** Allow passing a verifier challenge into the ceremony to embed inside the `SeedFingerprint` and `report_data`.

## 5. Atomic File Operations (E4/E6)
**Problem:** If the machine loses power exactly between writing the report and the sealed seed, the seed is wiped from RAM but never makes it to disk, permanently destroying the key.
**Fix:** Rewrite the file output logic to write to `.tmp` files, call `fsync` on the file descriptors, and then atomically `rename` them to their final paths.
