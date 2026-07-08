use sev::firmware::guest::Firmware;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use zns_keys::attestation::{
    generate_attestation_proof_with_challenge, seal_seed, unseal_seed, verify_report_binding,
};
use zns_keys::keyfile::{KeyFile, PlainSeed};
use zns_keys::seedhash::SeedFingerprint;

const DEFAULT_KEY_FILE: &str = "zns_keys.key";
const DEFAULT_REPORT: &str = "zns_attestation.report";
const DEFAULT_SOCKET: &str = "zns-keys.sock";

type AppResult<T> = Result<T, String>;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    #[cfg(not(target_arch = "x86_64"))]
    return Err("zns-keys must run on x86_64 AMD SEV-SNP capable CPUs".to_string());

    #[cfg(target_arch = "x86_64")]
    {
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
            "migrate-export" | "migrate-import" => Err(
                "migration is intentionally not implemented in v1; add attested DH/HPKE later"
                    .to_string(),
            ),
            "help" | "--help" | "-h" => {
                usage();
                Ok(())
            }
            other => Err(format!("unknown command `{other}`")),
        }
    }
}

fn usage() {
    eprintln!(
        "\
zns-keys: SEV-SNP key custody daemon for ZNS

commands:
  init [--key-file PATH] [--report PATH] [--challenge-hex HEX64]
  status [--key-file PATH]
  attest [--key-file PATH] [--report PATH] [--challenge-hex HEX64]
  verify [--key-file PATH] [--report PATH] [--challenge-hex HEX64]
  serve [--key-file PATH] [--socket PATH]
  migrate-export   (reserved for v2)
  migrate-import   (reserved for v2)
"
    );
}

fn cmd_init(args: &[String]) -> AppResult<()> {
    let key_file_path = option_path(args, "--key-file", DEFAULT_KEY_FILE)?;
    let report_path = option_path(args, "--report", DEFAULT_REPORT)?;
    let challenge = option_challenge(args)?;
    reject_unknown_options(args, &["--key-file", "--report", "--challenge-hex"])?;

    if key_file_path.exists() {
        return Err(format!(
            "key file already exists: {}",
            key_file_path.display()
        ));
    }
    if report_path.exists() {
        return Err(format!(
            "report file already exists: {}",
            report_path.display()
        ));
    }

    let seed = PlainSeed::generate();
    let fingerprint = seed.fingerprint();

    let mut firmware =
        Firmware::open().map_err(|err| format!("failed to open /dev/sev-guest: {err}"))?;
    let report = generate_attestation_proof_with_challenge(&mut firmware, &fingerprint, challenge);
    let sealed_seed = seal_seed(&mut firmware, &seed, &fingerprint);

    let key_file = KeyFile::new(fingerprint, sealed_seed);
    write_new_file(&key_file_path, &key_file.encode())?;
    write_new_file(&report_path, &report)?;

    println!("initialized zns-keys key file");
    println!("key file: {}", key_file_path.display());
    println!("report: {}", report_path.display());
    println!("fingerprint: {}", fingerprint);

    Ok(())
}

fn cmd_status(args: &[String]) -> AppResult<()> {
    let key_file_path = option_path(args, "--key-file", DEFAULT_KEY_FILE)?;
    reject_unknown_options(args, &["--key-file"])?;

    let key_file = KeyFile::read(&key_file_path)?;
    println!("key file: {}", key_file_path.display());
    println!("fingerprint: {}", key_file.fingerprint());
    Ok(())
}

fn cmd_attest(args: &[String]) -> AppResult<()> {
    let key_file_path = option_path(args, "--key-file", DEFAULT_KEY_FILE)?;
    let report_path = option_path(args, "--report", DEFAULT_REPORT)?;
    let challenge = option_challenge(args)?;
    reject_unknown_options(args, &["--key-file", "--report", "--challenge-hex"])?;

    let key_file = KeyFile::read(&key_file_path)?;
    let mut firmware =
        Firmware::open().map_err(|err| format!("failed to open /dev/sev-guest: {err}"))?;
    let report = generate_attestation_proof_with_challenge(
        &mut firmware,
        &key_file.fingerprint(),
        challenge,
    );

    write_new_file(&report_path, &report)?;
    println!("wrote attestation report: {}", report_path.display());
    println!("fingerprint: {}", key_file.fingerprint());
    Ok(())
}

fn cmd_verify(args: &[String]) -> AppResult<()> {
    let key_file_path = option_path(args, "--key-file", DEFAULT_KEY_FILE)?;
    let report_path = option_path(args, "--report", DEFAULT_REPORT)?;
    let challenge = option_challenge(args)?;
    reject_unknown_options(args, &["--key-file", "--report", "--challenge-hex"])?;

    let key_file = KeyFile::read(&key_file_path)?;
    let report = fs::read(&report_path)
        .map_err(|err| format!("failed to read report {}: {err}", report_path.display()))?;
    verify_report_binding(&report, &key_file.fingerprint(), challenge)?;

    println!("report binds expected fingerprint/challenge");
    println!("fingerprint: {}", key_file.fingerprint());
    println!("note: this structural check does not validate the AMD VCEK certificate chain");
    Ok(())
}

fn cmd_serve(args: &[String]) -> AppResult<()> {
    let key_file_path = option_path(args, "--key-file", DEFAULT_KEY_FILE)?;
    let socket_path = option_path(args, "--socket", DEFAULT_SOCKET)?;
    reject_unknown_options(args, &["--key-file", "--socket"])?;

    let key_file = KeyFile::read(&key_file_path)?;
    let mut firmware =
        Firmware::open().map_err(|err| format!("failed to open /dev/sev-guest: {err}"))?;
    let seed = unseal_seed(
        &mut firmware,
        key_file.sealed_seed(),
        &key_file.fingerprint(),
    );

    prepare_socket_path(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("failed to bind socket {}: {err}", socket_path.display()))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "failed to set socket permissions {}: {err}",
            socket_path.display()
        )
    })?;

    println!("zns-keys serving");
    println!("socket: {}", socket_path.display());
    println!("fingerprint: {}", key_file.fingerprint());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = handle_client(stream, key_file.fingerprint(), &seed) {
                    eprintln!("client error: {err}");
                }
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }

    Ok(())
}

fn handle_client(
    stream: UnixStream,
    fingerprint: SeedFingerprint,
    seed: &PlainSeed,
) -> AppResult<()> {
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
            .map_err(|err| format!("failed to write response: {err}"))?;
        writer
            .write_all(b"\n")
            .map_err(|err| format!("failed to write response newline: {err}"))?;
    }
}

fn handle_request(request: &str, fingerprint: SeedFingerprint, seed: &PlainSeed) -> String {
    if request == "status" {
        return format!("OK fingerprint {}", fingerprint);
    }

    if request == "attest" {
        return "ERR attest over RPC is not implemented; use `zns-keys attest`".to_string();
    }

    if let Some(rest) = request.strip_prefix("sign ") {
        let Ok(message) = decode_hex(rest) else {
            return "ERR sign payload must be hex".to_string();
        };
        return sign_orchard_placeholder(seed, &message);
    }

    "ERR unknown command; expected status, attest, or sign <hex>".to_string()
}

fn sign_orchard_placeholder(_seed: &PlainSeed, _message: &[u8]) -> String {
    "ERR Orchard/Pallas signing is not implemented in this crate yet".to_string()
}

fn write_new_file(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let tmp = temp_path(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|err| format!("failed to create temp file {}: {err}", tmp.display()))?;

    let write_result = (|| -> AppResult<()> {
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

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }

    write_result
}

fn temp_path(path: &Path) -> AppResult<PathBuf> {
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

fn sync_parent(path: &Path) -> AppResult<()> {
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

fn prepare_socket_path(path: &Path) -> AppResult<()> {
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

fn option_path(args: &[String], name: &str, default: &str) -> AppResult<PathBuf> {
    let mut value = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            let Some(next) = args.get(i + 1) else {
                return Err(format!("missing value for {name}"));
            };
            value = Some(PathBuf::from(next));
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(value.unwrap_or_else(|| PathBuf::from(default)))
}

fn option_challenge(args: &[String]) -> AppResult<[u8; 32]> {
    let mut challenge = [0u8; 32];
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--challenge-hex" {
            let Some(next) = args.get(i + 1) else {
                return Err("missing value for --challenge-hex".to_string());
            };
            let decoded = decode_hex(next)?;
            if decoded.len() != 32 {
                return Err("--challenge-hex must decode to exactly 32 bytes".to_string());
            }
            challenge.copy_from_slice(&decoded);
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(challenge)
}

fn reject_unknown_options(args: &[String], allowed: &[&str]) -> AppResult<()> {
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            if !allowed.contains(&args[i].as_str()) {
                return Err(format!("unknown option `{}`", args[i]));
            }
            i += 2;
        } else {
            return Err(format!("unexpected argument `{}`", args[i]));
        }
    }
    Ok(())
}

fn decode_hex(input: &str) -> AppResult<Vec<u8>> {
    let input = input.trim();
    if input.len() % 2 != 0 {
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

fn hex_value(byte: u8) -> AppResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character".to_string()),
    }
}
