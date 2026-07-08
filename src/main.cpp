#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <x86intrin.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

// Definitions for SEV-SNP guest ioctls
#define SNP_GET_REPORT _IOWR('S', 0, struct snp_guest_request_ioctl)
#define SNP_GET_DERIVED_KEY _IOWR('S', 1, struct snp_guest_request_ioctl)

struct snp_guest_request_ioctl {
    uint8_t msg_version;
    uint64_t req_data;
    uint64_t resp_data;
    uint64_t fw_err;
};

struct snp_report_req {
    uint8_t report_data[64];
    uint32_t vmpl;
    uint8_t reserved[28];
};

struct snp_report_resp {
    uint32_t status;
    uint32_t report_size;
    uint8_t reserved[24];
    uint8_t report[1184]; 
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
        std::cerr << "Length must be a multiple of 8\n";
        exit(1);
    }
    
    size_t chunks = len / 8;
    for (size_t i = 0; i < chunks; i++) {
        unsigned long long val = 0;
        int retries = 0;
        bool success = false;
        
        // Audit Finding #11: Bound the RDSEED spin loop to prevent hanging
        while (retries < 10000) {
            if (_rdseed64_step(&val) == 1) {
                memcpy(dest + (i * 8), &val, 8);
                success = true;
                break;
            } else {
                _mm_pause();
                retries++;
            }
        }
        
        if (!success) {
            std::cerr << "Hardware entropy pool exhausted after 10,000 retries. Aborting.\n";
            exit(1);
        }
    }
}

std::vector<uint8_t> generate_attestation_proof(int fd, const uint8_t* fingerprint) {
    std::cout << "Requesting Attestation Report from AMD Secure Processor...\n";
    
    snp_report_req req;
    memset(&req, 0, sizeof(req));
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
    
    // Audit Finding #5: Check firmware status to prevent silent failures
    if (ioctl_req.fw_err != 0 || resp.status != 0) {
        std::cerr << "Firmware error during attestation report generation. Aborting.\n";
        exit(1);
    }
    
    std::vector<uint8_t> report_bytes(sizeof(resp.report));
    memcpy(report_bytes.data(), resp.report, sizeof(resp.report));
    return report_bytes;
}

std::vector<uint8_t> seal_to_hardware(int fd, const uint8_t* seed) {
    std::cout << "Requesting derived sealing key from AMD Secure Processor...\n";
    
    snp_derived_key_req req;
    memset(&req, 0, sizeof(req));
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
    
    // Audit Finding #5: Check derived key firmware status
    if (ioctl_req.fw_err != 0 || resp.status != 0) {
        std::cerr << "Firmware error during hardware key derivation. Aborting.\n";
        OPENSSL_cleanse(resp.key, sizeof(resp.key));
        exit(1);
    }
    
    std::cout << "Encrypting seed with AMD hardware-derived key...\n";
    
    uint8_t nonce[12];
    uint8_t raw_nonce_buf[16];
    generate_rdseed_bytes(raw_nonce_buf, sizeof(raw_nonce_buf));
    memcpy(nonce, raw_nonce_buf, 12);
    OPENSSL_cleanse(raw_nonce_buf, sizeof(raw_nonce_buf));
    
    // Audit Finding #4: Check ctx for NULL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "EVP_CIPHER_CTX_new failed\n";
        OPENSSL_cleanse(resp.key, sizeof(resp.key));
        exit(1);
    }
    
    // Audit Finding #4: Check AEAD returns explicitly
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, resp.key, nonce) != 1) {
        std::cerr << "EVP_EncryptInit_ex failed\n";
        OPENSSL_cleanse(resp.key, sizeof(resp.key));
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    
    // Audit Finding #3: Explicitly zeroize hardware key immediately after feeding it to the cipher
    OPENSSL_cleanse(resp.key, sizeof(resp.key)); 
    
    std::vector<uint8_t> ciphertext(32);
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, seed, 32) != 1) {
        std::cerr << "EVP_EncryptUpdate failed\n";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    
    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        std::cerr << "EVP_EncryptFinal_ex failed\n";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    ciphertext_len += len;
    
    if (ciphertext_len != 32) {
        std::cerr << "Ciphertext length mismatch\n";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    
    uint8_t mac[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, mac) != 1) {
        std::cerr << "Failed to get MAC tag\n";
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    std::vector<uint8_t> sealed_blob(60);
    memcpy(sealed_blob.data(), nonce, 12);
    memcpy(sealed_blob.data() + 12, ciphertext.data(), 32);
    memcpy(sealed_blob.data() + 44, mac, 16);
    
    // Cleanse stack variables before returning
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(mac, sizeof(mac));
    
    return sealed_blob;
}

// Helper to write securely (Audit Finding #6 & #7)
void write_secure_file(const char* filepath, const std::vector<uint8_t>& data) {
    // O_EXCL prevents symlink follow, 0600 prevents world-reads
    int fd = open(filepath, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        perror("Failed to safely open file for writing (O_EXCL)");
        exit(1);
    }
    
    ssize_t written = ::write(fd, data.data(), data.size());
    if (written < 0 || (size_t)written != data.size()) {
        perror("Failed to write full file data");
        close(fd);
        exit(1);
    }
    
    close(fd);
}

int main() {
    std::cout << "=== ZNS Mint: AMD SEV-SNP Key Generation Ceremony ===\n";
    
    uint8_t seed[32];
    generate_rdseed_bytes(seed, sizeof(seed));
    
    // Audit Finding #1: Proper one-way fingerprint commitment (mimicking Rust blake2b behavior)
    uint8_t fingerprint[32];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Failed to create MD context\n";
        OPENSSL_cleanse(seed, sizeof(seed));
        exit(1);
    }
    
    // Using SHA-256 (in lieu of Blake2b-256 for a standard OpenSSL 1.1 environment)
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        std::cerr << "Failed to init digest\n";
        OPENSSL_cleanse(seed, sizeof(seed));
        exit(1);
    }
    
    const char* personalization = "ZcashSeedFpV1\0\0\0";
    uint8_t seed_len = 32;
    EVP_DigestUpdate(mdctx, personalization, 16);
    EVP_DigestUpdate(mdctx, &seed_len, 1);
    EVP_DigestUpdate(mdctx, seed, 32);
    
    unsigned int md_len = 0;
    EVP_DigestFinal_ex(mdctx, fingerprint, &md_len);
    EVP_MD_CTX_free(mdctx);
    
    std::cout << "✅ Generated true hardware entropy via RDSEED.\n";
    
    int fd = open("/dev/sev-guest", O_RDWR);
    if (fd < 0) {
        // Audit Finding #2: Fail closed instead of open
        std::cerr << "Failed to open /dev/sev-guest. Aborting ceremony.\n";
        OPENSSL_cleanse(seed, sizeof(seed));
        exit(1);
    }
    
    auto report_bytes = generate_attestation_proof(fd, fingerprint);
    write_secure_file("zns_attestation.report", report_bytes);
    std::cout << "✅ Saved AMD hardware signature proof to `zns_attestation.report`\n";

    auto sealed_blob = seal_to_hardware(fd, seed);
    write_secure_file("sealed_seed.bin", sealed_blob);
    std::cout << "✅ Saved 60-byte hardware-sealed encrypted seed to `sealed_seed.bin`\n";
    
    close(fd);
    
    std::cout << "=====================================================\n";
    std::cout << "Ceremony complete. Destroying seed in memory.\n";
    
    // Audit Finding #3: Explicit compiler-safe memory wipe
    OPENSSL_cleanse(seed, sizeof(seed)); 
    
    return 0;
}
