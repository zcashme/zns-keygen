#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <x86intrin.h>
#include <fstream>
// Assuming OpenSSL for ChaCha20-Poly1305
#include <openssl/evp.h>

// Definitions for SEV-SNP guest ioctls (simplified)
#define SNP_GET_REPORT _IOWR('S', 0, struct snp_guest_request_ioctl)
#define SNP_GET_DERIVED_KEY _IOWR('S', 1, struct snp_guest_request_ioctl)

struct snp_guest_request_ioctl {
    uint8_t msg_version;
    uint64_t req_data;
    uint64_t resp_data;
    uint64_t fw_err;
};

// Simplified structures for SEV-SNP
struct snp_report_req {
    uint8_t report_data[64];
    uint32_t vmpl;
    uint8_t reserved[28];
};

struct snp_report_resp {
    uint32_t status;
    uint32_t report_size;
    uint8_t reserved[24];
    uint8_t report[1184]; // The actual attestation report
};

struct snp_derived_key_req {
    uint32_t root_key_select;
    uint32_t reserved;
    uint64_t guest_field_select;
    uint32_t vmpl;
    uint32_t mix_osinfo;
    uint8_t reserved2[104];
};

struct snp_derived_key_resp {
    uint32_t status;
    uint8_t reserved[28];
    uint8_t key[32];
};

void generate_rdseed_bytes(uint8_t* dest, size_t len) {
    if (len % 8 != 0) {
        std::cerr << "Length must be a multiple of 8" << std::endl;
        exit(1);
    }
    
    size_t chunks = len / 8;
    for (size_t i = 0; i < chunks; i++) {
        unsigned long long val = 0;
        // Attempt to read hardware entropy
        while (_rdseed64_step(&val) != 1) {
            _mm_pause(); // Yield if the hardware entropy pool is empty
        }
        memcpy(dest + (i * 8), &val, 8);
    }
}

std::vector<uint8_t> generate_attestation_proof(int fd, const uint8_t* fingerprint) {
    std::cout << "Requesting Attestation Report from AMD Secure Processor...\n";
    
    snp_report_req req;
    memset(&req, 0, sizeof(req));
    
    // Copy the 32-byte fingerprint into the first 32 bytes of report_data
    memcpy(req.report_data, fingerprint, 32);
    
    snp_report_resp resp;
    memset(&resp, 0, sizeof(resp));
    
    snp_guest_request_ioctl ioctl_req;
    memset(&ioctl_req, 0, sizeof(ioctl_req));
    ioctl_req.msg_version = 1;
    ioctl_req.req_data = reinterpret_cast<uint64_t>(&req);
    ioctl_req.resp_data = reinterpret_cast<uint64_t>(&resp);
    
    if (ioctl(fd, SNP_GET_REPORT, &ioctl_req) < 0) {
        perror("Failed to get Attestation Report");
        exit(1);
    }
    
    // We'll just return the struct as bytes for the proof
    std::vector<uint8_t> report_bytes(sizeof(resp.report));
    memcpy(report_bytes.data(), resp.report, sizeof(resp.report));
    
    return report_bytes;
}

std::vector<uint8_t> seal_to_hardware(int fd, const uint8_t* seed) {
    std::cout << "Requesting derived sealing key from AMD Secure Processor...\n";
    
    snp_derived_key_req req;
    memset(&req, 0, sizeof(req));
    // GuestFieldSelect::MEASUREMENT (BIT 0 = 1) equivalent
    req.guest_field_select = 1; 
    
    snp_derived_key_resp resp;
    memset(&resp, 0, sizeof(resp));
    
    snp_guest_request_ioctl ioctl_req;
    memset(&ioctl_req, 0, sizeof(ioctl_req));
    ioctl_req.msg_version = 1;
    ioctl_req.req_data = reinterpret_cast<uint64_t>(&req);
    ioctl_req.resp_data = reinterpret_cast<uint64_t>(&resp);
    
    if (ioctl(fd, SNP_GET_DERIVED_KEY, &ioctl_req) < 0) {
        perror("Failed to derive hardware key");
        exit(1);
    }
    
    std::cout << "Encrypting seed with AMD hardware-derived key...\n";
    
    uint8_t nonce[12];
    uint8_t raw_nonce_buf[16];
    generate_rdseed_bytes(raw_nonce_buf, sizeof(raw_nonce_buf));
    memcpy(nonce, raw_nonce_buf, 12);
    
    // Using OpenSSL for ChaCha20-Poly1305
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, resp.key, nonce);
    
    // WARNING: In C++, the developer must explicitly zeroize the key buffer
    // memset(resp.key, 0, sizeof(resp.key)); 
    // ^ If they forget this or if compiler optimizes it out, key leaks in RAM!
    
    std::vector<uint8_t> ciphertext(32); // 32 bytes seed
    int len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, seed, 32);
    
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    
    uint8_t mac[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, mac);
    EVP_CIPHER_CTX_free(ctx);
    
    // Construct the 60-byte blob
    std::vector<uint8_t> sealed_blob(60);
    memcpy(sealed_blob.data(), nonce, 12);
    memcpy(sealed_blob.data() + 12, ciphertext.data(), 32);
    memcpy(sealed_blob.data() + 44, mac, 16);
    
    return sealed_blob;
}

int main() {
    std::cout << "=== ZNS Mint: AMD SEV-SNP Key Generation Ceremony ===\n";
    
    // Step 1: Hardware Entropy
    uint8_t seed[32]; // Notice this is a raw array, not a specialized type
    generate_rdseed_bytes(seed, sizeof(seed));
    
    // Create a mock fingerprint (since zip32 is rust-specific)
    // We'll just hash the seed in real life. Let's pretend this is the fingerprint.
    uint8_t fingerprint[32];
    for(int i = 0; i < 32; i++) fingerprint[i] = seed[i] ^ 0xAA; 
    
    std::cout << "✅ Generated true hardware entropy via RDSEED.\n";
    // WARNING: It's very easy to accidentally print the secret in C++
    // std::cout << "Seed is: " << seed << "\n"; // This could accidentally leak!
    
    int fd = open("/dev/sev-guest", O_RDWR);
    if (fd < 0) {
        std::cerr << "Failed to open /dev/sev-guest (is this an SEV-SNP VM?)\n";
        // We'll continue for demonstration purposes or exit in production
        // exit(1);
    }
    
    // Step 2: Cryptographic Proof
    if (fd >= 0) {
        auto report_bytes = generate_attestation_proof(fd, fingerprint);
        std::ofstream report_file("zns_attestation.report", std::ios::binary);
        report_file.write(reinterpret_cast<const char*>(report_bytes.data()), report_bytes.size());
        std::cout << "✅ Saved AMD hardware signature proof to `zns_attestation.report`\n";
    }

    // Step 3: Hardware Sealing
    if (fd >= 0) {
        auto sealed_blob = seal_to_hardware(fd, seed);
        std::ofstream sealed_file("sealed_seed.bin", std::ios::binary);
        sealed_file.write(reinterpret_cast<const char*>(sealed_blob.data()), sealed_blob.size());
        std::cout << "✅ Saved 60-byte hardware-sealed encrypted seed to `sealed_seed.bin`\n";
        
        close(fd);
    }
    
    std::cout << "=====================================================\n";
    std::cout << "Ceremony complete. No human has seen the seed.\n";
    
    // WARNING: In C++, the `seed` array is still sitting in stack memory here.
    // If we return, the memory might be reused and leaked!
    // We MUST manually do something like:
    // memset(seed, 0, sizeof(seed)); 
    // And even then, `memset` is often optimized away by the compiler!
    // (We would need OPENSSL_cleanse, explicit_bzero, etc.)
    
    return 0;
}
