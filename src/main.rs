use bech32::{Bech32, Hrp};
use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use sev::{firmware::guest::AttestationReport, parser::ByteParser};
use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
#[cfg(target_arch = "x86_64")]
use std::hint::spin_loop;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_SEED_FILE: &str = "zns_seed.sealed";
const DEFAULT_REPORT_FILE: &str = "zns_attestation.report";
const DEFAULT_SOCKET: &str = "zns-keys.sock";

const SEED_LEN: usize = 32;
const FINGERPRINT_LEN: usize = 32;
const SEALING_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CIPHERTEXT_LEN: usize = SEED_LEN + TAG_LEN;

const SEALED_MAGIC: &[u8; 8] = b"ZNSSEED1";
const SEALED_VERSION: u32 = 1;
const SEALED_HEADER_LEN: usize = 8 + 4 + FINGERPRINT_LEN;
const SEALED_FILE_LEN: usize = SEALED_HEADER_LEN + NONCE_LEN + CIPHERTEXT_LEN;
const FINGERPRINT_PERSONALIZATION: &[u8; 16] = b"ZcashSeedFpV1\0\0\0";
const FINGERPRINT_HRP: Hrp = Hrp::parse_unchecked("zip32seedfp");

type ZnsResult<T> = Result<T, String>;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> ZnsResult<()> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return Ok(());
    }

    let command = args.remove(0);
    match command.as_str() {
        "init" => cmd_init(&args),
        "status" => cmd_status(&args),
        "attest" => cmd_attest(&args),
        "verify" => cmd_verify(&args),
        "serve" => cmd_serve(&args),
        "help" | "--help" | "-h" => {
            usage();
            Ok(())
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

fn usage() {
    eprintln!(
        "\
zns-keys: attested seed custody signer

commands:
  init [--seed-file PATH] [--report PATH] [--challenge-hex HEX64]
  status [--seed-file PATH]
  attest [--seed-file PATH] [--report PATH] [--challenge-hex HEX64]
  verify [--seed-file PATH] [--report PATH] [--challenge-hex HEX64]
  serve [--seed-file PATH] [--socket PATH]

defaults:
  seed file: {DEFAULT_SEED_FILE}
  report:    {DEFAULT_REPORT_FILE}
  socket:    {DEFAULT_SOCKET}
"
    );
}

fn cmd_init(args: &[String]) -> ZnsResult<()> {
    let options = Options::parse(args, &["--seed-file", "--report", "--challenge-hex"])?;

    if options.seed_file.exists() {
        return Err(format!(
            "sealed seed file already exists: {}",
            options.seed_file.display()
        ));
    }
    if options.report.exists() {
        return Err(format!(
            "attestation report already exists: {}",
            options.report.display()
        ));
    }

    let seed = Seed::generate()?;
    let fingerprint = seed.fingerprint()?;
    let report = sev_attestation_report(fingerprint, options.challenge)?;
    let sealing_key = derive_sev_sealing_key()?;
    let sealed_seed = seal_seed(&seed, &sealing_key, fingerprint)?;

    write_new_file(&options.seed_file, &sealed_seed.encode())?;
    write_new_file(&options.report, &report)?;

    println!("initialized zns-keys custody seed");
    println!("sealed seed file: {}", options.seed_file.display());
    println!("attestation report: {}", options.report.display());
    println!("fingerprint: {}", fingerprint);
    Ok(())
}

fn cmd_status(args: &[String]) -> ZnsResult<()> {
    let options = Options::parse(args, &["--seed-file"])?;

    let sealed_seed = SealedSeed::read(&options.seed_file)?;
    println!("sealed seed file: {}", options.seed_file.display());
    println!("fingerprint: {}", sealed_seed.fingerprint);
    Ok(())
}

fn cmd_attest(args: &[String]) -> ZnsResult<()> {
    let options = Options::parse(args, &["--seed-file", "--report", "--challenge-hex"])?;

    let sealed_seed = SealedSeed::read(&options.seed_file)?;
    let report = sev_attestation_report(sealed_seed.fingerprint, options.challenge)?;
    write_new_file(&options.report, &report)?;

    println!("wrote attestation report: {}", options.report.display());
    println!("fingerprint: {}", sealed_seed.fingerprint);
    Ok(())
}

fn cmd_verify(args: &[String]) -> ZnsResult<()> {
    let options = Options::parse(args, &["--seed-file", "--report", "--challenge-hex"])?;

    let sealed_seed = SealedSeed::read(&options.seed_file)?;
    let report = fs::read(&options.report)
        .map_err(|err| format!("failed to read report {}: {err}", options.report.display()))?;
    verify_report_binding(&report, sealed_seed.fingerprint, options.challenge)?;

    println!("report binds expected fingerprint/challenge");
    println!("fingerprint: {}", sealed_seed.fingerprint);
    println!("note: this structural check does not validate the AMD certificate chain");
    Ok(())
}

fn cmd_serve(args: &[String]) -> ZnsResult<()> {
    let options = Options::parse(args, &["--seed-file", "--socket"])?;

    let sealed_seed = SealedSeed::read(&options.seed_file)?;
    let sealing_key = derive_sev_sealing_key()?;
    let seed = unseal_seed(&sealed_seed, &sealing_key)?;

    prepare_socket_path(&options.socket)?;
    let listener = UnixListener::bind(&options.socket)
        .map_err(|err| format!("failed to bind socket {}: {err}", options.socket.display()))?;
    fs::set_permissions(&options.socket, fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "failed to set socket permissions {}: {err}",
            options.socket.display()
        )
    })?;

    println!("zns-keys serving");
    println!("socket: {}", options.socket.display());
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

struct Options {
    seed_file: PathBuf,
    report: PathBuf,
    socket: PathBuf,
    challenge: [u8; SEED_LEN],
}

impl Options {
    fn parse(args: &[String], allowed: &[&str]) -> ZnsResult<Options> {
        let mut options = Options {
            seed_file: PathBuf::from(DEFAULT_SEED_FILE),
            report: PathBuf::from(DEFAULT_REPORT_FILE),
            socket: PathBuf::from(DEFAULT_SOCKET),
            challenge: [0u8; SEED_LEN],
        };

        let mut i = 0;
        while i < args.len() {
            let name = &args[i];
            if !name.starts_with("--") {
                return Err(format!("unexpected argument `{name}`"));
            }
            if !allowed.contains(&name.as_str()) {
                return Err(format!("unknown option `{name}`"));
            }

            let value = args
                .get(i + 1)
                .ok_or_else(|| format!("missing value for {name}"))?;

            match name.as_str() {
                "--seed-file" => options.seed_file = PathBuf::from(value),
                "--report" => options.report = PathBuf::from(value),
                "--socket" => options.socket = PathBuf::from(value),
                "--challenge-hex" => {
                    options.challenge = decode_hex_array(value, "--challenge-hex")?;
                }
                _ => unreachable!("allowed option has no parser"),
            }

            i += 2;
        }

        Ok(options)
    }
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
        if &bytes[0..8] != SEALED_MAGIC {
            return Err("invalid sealed seed magic".to_string());
        }

        let version = u32::from_le_bytes(bytes[8..12].try_into().expect("version length fixed"));
        if version != SEALED_VERSION {
            return Err(format!("unsupported sealed seed version: {version}"));
        }

        Ok(SealedSeed {
            fingerprint: SeedFingerprint::from_bytes(
                bytes[12..44].try_into().expect("fingerprint length fixed"),
            ),
            nonce: bytes[44..68].try_into().expect("nonce length fixed"),
            ciphertext: bytes[68..SEALED_FILE_LEN]
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
    header[0..8].copy_from_slice(SEALED_MAGIC);
    header[8..12].copy_from_slice(&SEALED_VERSION.to_le_bytes());
    header[12..44].copy_from_slice(&fingerprint.to_bytes());
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
        let Ok(message) = decode_hex(rest) else {
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

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn sev_attestation_report(
    fingerprint: SeedFingerprint,
    challenge: [u8; SEED_LEN],
) -> ZnsResult<Vec<u8>> {
    let report_data = report_data(fingerprint, challenge);
    let mut firmware =
        Firmware::open().map_err(|err| format!("failed to open /dev/sev-guest: {err}"))?;
    firmware
        .get_report(None, Some(report_data), None)
        .map_err(|err| format!("failed to get SEV-SNP attestation report: {err}"))
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn sev_attestation_report(
    _fingerprint: SeedFingerprint,
    _challenge: [u8; SEED_LEN],
) -> ZnsResult<Vec<u8>> {
    Err("SEV-SNP attestation requires Linux x86_64 with /dev/sev-guest".to_string())
}

fn report_data(fingerprint: SeedFingerprint, challenge: [u8; SEED_LEN]) -> [u8; 64] {
    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(&fingerprint.to_bytes());
    report_data[32..64].copy_from_slice(&challenge);
    report_data
}

fn verify_report_binding(
    report_bytes: &[u8],
    fingerprint: SeedFingerprint,
    challenge: [u8; SEED_LEN],
) -> ZnsResult<()> {
    let report = AttestationReport::from_bytes(report_bytes)
        .map_err(|err| format!("failed to parse SEV-SNP report: {err}"))?;
    let expected = report_data(fingerprint, challenge);

    if report.report_data != expected {
        return Err("report_data does not bind expected fingerprint/challenge".to_string());
    }

    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> ZnsResult<()> {
    let tmp = temp_path(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|err| format!("failed to create temp file {}: {err}", tmp.display()))?;

    let result = (|| -> ZnsResult<()> {
        file.write_all(bytes)
            .map_err(|err| format!("failed to write temp file {}: {err}", tmp.display()))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync temp file {}: {err}", tmp.display()))?;
        fs::hard_link(&tmp, path).map_err(|err| {
            format!(
                "failed to publish {} from temp file {}: {err}",
                path.display(),
                tmp.display()
            )
        })?;
        fs::remove_file(&tmp)
            .map_err(|err| format!("failed to remove temp file {}: {err}", tmp.display()))?;
        sync_parent(path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }

    result
}

fn temp_path(path: &Path) -> ZnsResult<PathBuf> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("path has no file name: {}", path.display()))?
        .to_string_lossy();
    let tmp_name = format!(".{file_name}.tmp.{}", std::process::id());

    Ok(match parent {
        Some(parent) => parent.join(tmp_name),
        None => PathBuf::from(tmp_name),
    })
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

fn decode_hex(input: &str) -> ZnsResult<Vec<u8>> {
    let input = input.trim();
    if !input.len().is_multiple_of(2) {
        return Err("hex input must have even length".to_string());
    }

    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_value(bytes[i])?;
        let lo = hex_value(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn decode_hex_array<const N: usize>(input: &str, name: &str) -> ZnsResult<[u8; N]> {
    let decoded = decode_hex(input)?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "{name} must decode to exactly {N} bytes, got {}",
            bytes.len()
        )
    })
}

fn hex_value(byte: u8) -> ZnsResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character".to_string()),
    }
}
