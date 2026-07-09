use bech32::{Bech32, Hrp};
use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use std::fmt;
use std::fs::{self, File, OpenOptions};
#[cfg(target_arch = "x86_64")]
use std::hint::spin_loop;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_SEED_FILE: &str = "zns_seed.sealed";
const DEFAULT_SOCKET: &str = "zns-keys.sock";

const SEED_LEN: usize = 32;
const FINGERPRINT_LEN: usize = 32;
const SEALING_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CIPHERTEXT_LEN: usize = SEED_LEN + TAG_LEN;

const DOMAIN_TAG: &[u8; 10] = b"ZcashNames";
const SEALED_MAGIC_LEN: usize = 10;
const SEALED_HEADER_LEN: usize = SEALED_MAGIC_LEN + FINGERPRINT_LEN;
const SEALED_FILE_LEN: usize = SEALED_HEADER_LEN + NONCE_LEN + CIPHERTEXT_LEN;
const FINGERPRINT_PERSONALIZATION: &[u8; 16] = b"ZcashNames\0\0\0\0\0\0";
const FINGERPRINT_HRP: Hrp = Hrp::parse_unchecked("zcashnames");

type ZnsResult<T> = Result<T, String>;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> ZnsResult<()> {
    let seed_path = Path::new(DEFAULT_SEED_FILE);
    let socket_path = Path::new(DEFAULT_SOCKET);

    if !seed_path.exists() {
        println!("No sealed seed found. Generating new custody seed...");
        let seed = Seed::generate()?;
        let fingerprint = seed.fingerprint()?;
        let sealing_key = derive_sev_sealing_key()?;
        let sealed_seed = seal_seed(&seed, &sealing_key, fingerprint)?;
        write_new_file(seed_path, &sealed_seed.encode())?;
        println!("Sealed seed saved to {}", seed_path.display());
    }

    let sealed_seed = SealedSeed::read(seed_path)?;
    let sealing_key = derive_sev_sealing_key()?;
    let seed = unseal_seed(&sealed_seed, &sealing_key)?;

    prepare_socket_path(socket_path)?;
    let listener = UnixListener::bind(socket_path)
        .map_err(|err| format!("failed to bind socket {}: {err}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "failed to set socket permissions {}: {err}",
            socket_path.display()
        )
    })?;

    println!("zns-keys serving");
    println!("socket: {}", socket_path.display());
    println!("fingerprint: {}", sealed_seed.fingerprint);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = handle_client(stream, sealed_seed.fingerprint, &seed) {
                    eprintln!("client error: {err}");
                }
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }

    Ok(())
}

struct Seed(Zeroizing<[u8; SEED_LEN]>);

impl Seed {
    fn generate() -> ZnsResult<Seed> {
        let mut seed = Seed(Zeroizing::new([0u8; SEED_LEN]));
        fill_entropy(&mut seed.0[..])?;
        Ok(seed)
    }

    fn from_plaintext(plaintext: &mut [u8]) -> ZnsResult<Seed> {
        if plaintext.len() != SEED_LEN {
            return Err(format!(
                "decrypted seed length was {}, expected {SEED_LEN}",
                plaintext.len()
            ));
        }

        let mut seed = Seed(Zeroizing::new([0u8; SEED_LEN]));
        seed.0.copy_from_slice(plaintext);
        plaintext.zeroize();
        Ok(seed)
    }

    fn expose_for_signing<R>(&self, f: impl FnOnce(&[u8; SEED_LEN]) -> R) -> R {
        f(&self.0)
    }

    fn fingerprint(&self) -> ZnsResult<SeedFingerprint> {
        self.expose_for_signing(SeedFingerprint::from_seed)
    }
}

struct SealingKey(Zeroizing<[u8; SEALING_KEY_LEN]>);

impl SealingKey {
    fn as_bytes(&self) -> &[u8; SEALING_KEY_LEN] {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SeedFingerprint([u8; FINGERPRINT_LEN]);

impl SeedFingerprint {
    fn from_seed(seed: &[u8; SEED_LEN]) -> ZnsResult<SeedFingerprint> {
        Ok(SeedFingerprint(
            Blake2bParams::new()
                .hash_length(FINGERPRINT_LEN)
                .personal(FINGERPRINT_PERSONALIZATION)
                .to_state()
                .update(&[SEED_LEN as u8])
                .update(seed)
                .finalize()
                .as_bytes()
                .try_into()
                .map_err(|_| "fingerprint hash length mismatch".to_string())?,
        ))
    }

    fn from_bytes(bytes: [u8; FINGERPRINT_LEN]) -> SeedFingerprint {
        SeedFingerprint(bytes)
    }

    fn to_bytes(self) -> [u8; FINGERPRINT_LEN] {
        self.0
    }
}

impl fmt::Display for SeedFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match bech32::encode::<Bech32>(FINGERPRINT_HRP, &self.0) {
            Ok(encoded) => f.write_str(&encoded),
            Err(_) => {
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone)]
struct SealedSeed {
    fingerprint: SeedFingerprint,
    nonce: [u8; NONCE_LEN],
    ciphertext: [u8; CIPHERTEXT_LEN],
}

impl SealedSeed {
    fn encode(&self) -> [u8; SEALED_FILE_LEN] {
        let mut out = [0u8; SEALED_FILE_LEN];
        out[..SEALED_HEADER_LEN].copy_from_slice(&sealed_header(self.fingerprint));
        out[SEALED_HEADER_LEN..SEALED_HEADER_LEN + NONCE_LEN].copy_from_slice(&self.nonce);
        out[SEALED_HEADER_LEN + NONCE_LEN..].copy_from_slice(&self.ciphertext);
        out
    }

    fn decode(bytes: &[u8]) -> ZnsResult<SealedSeed> {
        if bytes.len() != SEALED_FILE_LEN {
            return Err(format!(
                "invalid sealed seed length: expected {SEALED_FILE_LEN}, got {}",
                bytes.len()
            ));
        }
        if &bytes[0..SEALED_MAGIC_LEN] != DOMAIN_TAG {
            return Err("invalid sealed seed magic".to_string());
        }

        Ok(SealedSeed {
            fingerprint: SeedFingerprint::from_bytes(
                bytes[SEALED_MAGIC_LEN..SEALED_MAGIC_LEN + FINGERPRINT_LEN]
                    .try_into()
                    .expect("fingerprint length fixed"),
            ),
            nonce: bytes[SEALED_MAGIC_LEN + FINGERPRINT_LEN
                ..SEALED_MAGIC_LEN + FINGERPRINT_LEN + NONCE_LEN]
                .try_into()
                .expect("nonce length fixed"),
            ciphertext: bytes[SEALED_MAGIC_LEN + FINGERPRINT_LEN + NONCE_LEN..SEALED_FILE_LEN]
                .try_into()
                .expect("ciphertext length fixed"),
        })
    }

    fn read(path: &Path) -> ZnsResult<SealedSeed> {
        let bytes = fs::read(path)
            .map_err(|err| format!("failed to read sealed seed file {}: {err}", path.display()))?;
        SealedSeed::decode(&bytes)
    }
}

fn seal_seed(
    seed: &Seed,
    sealing_key: &SealingKey,
    fingerprint: SeedFingerprint,
) -> ZnsResult<SealedSeed> {
    let cipher = XChaCha20Poly1305::new_from_slice(sealing_key.as_bytes())
        .map_err(|_| "invalid sealing key length".to_string())?;

    let mut nonce = [0u8; NONCE_LEN];
    fill_entropy(&mut nonce)?;
    let aad = seal_aad(fingerprint);
    let nonce_ref =
        <&XNonce>::try_from(nonce.as_slice()).map_err(|_| "invalid nonce length".to_string())?;
    let ciphertext = seed.expose_for_signing(|seed_bytes| {
        cipher.encrypt(
            nonce_ref,
            Payload {
                msg: seed_bytes,
                aad: &aad,
            },
        )
    });
    let ciphertext = ciphertext.map_err(|_| "failed to encrypt seed".to_string())?;

    Ok(SealedSeed {
        fingerprint,
        nonce,
        ciphertext: ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| "sealed seed ciphertext length mismatch".to_string())?,
    })
}

fn unseal_seed(sealed_seed: &SealedSeed, sealing_key: &SealingKey) -> ZnsResult<Seed> {
    let cipher = XChaCha20Poly1305::new_from_slice(sealing_key.as_bytes())
        .map_err(|_| "invalid sealing key length".to_string())?;
    let aad = seal_aad(sealed_seed.fingerprint);
    let nonce = <&XNonce>::try_from(sealed_seed.nonce.as_slice())
        .map_err(|_| "invalid nonce length".to_string())?;

    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &sealed_seed.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| "failed to decrypt sealed seed".to_string())?;

    let seed = Seed::from_plaintext(&mut plaintext)?;
    plaintext.zeroize();

    let actual_fingerprint = seed.fingerprint()?;
    if actual_fingerprint != sealed_seed.fingerprint {
        return Err("decrypted seed fingerprint mismatch".to_string());
    }

    Ok(seed)
}

fn seal_aad(fingerprint: SeedFingerprint) -> [u8; SEALED_HEADER_LEN] {
    sealed_header(fingerprint)
}

fn sealed_header(fingerprint: SeedFingerprint) -> [u8; SEALED_HEADER_LEN] {
    let mut header = [0u8; SEALED_HEADER_LEN];
    header[0..SEALED_MAGIC_LEN].copy_from_slice(DOMAIN_TAG);
    header[SEALED_MAGIC_LEN..SEALED_HEADER_LEN].copy_from_slice(&fingerprint.to_bytes());
    header
}

fn handle_client(stream: UnixStream, fingerprint: SeedFingerprint, seed: &Seed) -> ZnsResult<()> {
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|err| format!("failed to clone client stream: {err}"))?,
    );
    let mut writer = stream;
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .map_err(|err| format!("failed to read request: {err}"))?;
        if n == 0 {
            return Ok(());
        }

        let response = handle_request(line.trim_end(), fingerprint, seed);
        writer
            .write_all(response.as_bytes())
            .and_then(|_| writer.write_all(b"\n"))
            .map_err(|err| format!("failed to write response: {err}"))?;
    }
}

fn handle_request(request: &str, fingerprint: SeedFingerprint, seed: &Seed) -> String {
    if request == "status" {
        return format!("OK fingerprint {}", fingerprint);
    }

    if let Some(rest) = request.strip_prefix("sign ") {
        let Ok(message) = hex::decode(rest.trim()) else {
            return "ERR sign payload must be hex".to_string();
        };
        return sign_placeholder(seed, &message);
    }

    "ERR unknown command; expected status or sign <hex>".to_string()
}

fn sign_placeholder(_seed: &Seed, _message: &[u8]) -> String {
    "ERR signing is not implemented in v0".to_string()
}

#[cfg(target_arch = "x86_64")]
fn fill_entropy(dest: &mut [u8]) -> ZnsResult<()> {
    if dest.is_empty() {
        return Ok(());
    }

    let mut offset = 0;
    while offset < dest.len() {
        let mut value = 0u64;
        let mut success = false;

        for _ in 0..10_000 {
            unsafe {
                if core::arch::x86_64::_rdseed64_step(&mut value) == 1 {
                    success = true;
                    break;
                }
            }
            spin_loop();
        }

        if !success {
            return Err("RDSEED hardware entropy was unavailable".to_string());
        }

        let bytes = value.to_ne_bytes();
        let take = std::cmp::min(bytes.len(), dest.len() - offset);
        dest[offset..offset + take].copy_from_slice(&bytes[..take]);
        value.zeroize();
        offset += take;
    }

    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn fill_entropy(_dest: &mut [u8]) -> ZnsResult<()> {
    Err("zns-keys v0 requires x86_64 RDSEED entropy".to_string())
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn derive_sev_sealing_key() -> ZnsResult<SealingKey> {
    let mut firmware =
        Firmware::open().map_err(|err| format!("failed to open /dev/sev-guest: {err}"))?;
    let mut guest_fields = GuestFieldSelect::default();
    guest_fields.set_measurement(true);

    let request = DerivedKey::new(false, guest_fields, 0, 0, 0, None);
    let mut key = firmware
        .get_derived_key(None, request)
        .map_err(|err| format!("failed to derive SEV-SNP sealing key: {err}"))?;

    let sealing_key = SealingKey(Zeroizing::new(key));
    key.zeroize();
    Ok(sealing_key)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn derive_sev_sealing_key() -> ZnsResult<SealingKey> {
    Err("SEV-SNP sealing requires Linux x86_64 with /dev/sev-guest".to_string())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> ZnsResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("failed to create file {}: {err}", path.display()))?;

    file.write_all(bytes)
        .map_err(|err| format!("failed to write file {}: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("failed to sync file {}: {err}", path.display()))?;

    sync_parent(path)?;
    Ok(())
}

fn sync_parent(path: &Path) -> ZnsResult<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|err| {
            format!(
                "failed to sync parent directory {}: {err}",
                parent.display()
            )
        })
}

fn prepare_socket_path(path: &Path) -> ZnsResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_socket() {
                fs::remove_file(path).map_err(|err| {
                    format!("failed to remove stale socket {}: {err}", path.display())
                })?;
                Ok(())
            } else {
                Err(format!(
                    "socket path already exists and is not a socket: {}",
                    path.display()
                ))
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "failed to inspect socket path {}: {err}",
            path.display()
        )),
    }
}
