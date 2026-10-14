//! Access codes, separate from the seed ceremony.
//!
//! `zns-keygen access-code` unseals the seed capsule, prints the X25519
//! public key of `HMAC-SHA256(seed, "ZNS/access-code/x25519/v1")`, and drops
//! the seed. Nothing is written. The issuer agrees their private key with
//! the printed public key.
//!
//! `zns-keygen access-code code <name>` derives the same private key and
//! agrees it with the issuer's public key. The mint judges a name with that
//! shared secret: `purpose = HMAC-SHA256(shared, "access-code-v1")`, then
//! `u32_be(HMAC-SHA256(purpose, name)[0..4]) mod 1_000_000`.

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;
use zns_canon::access_code::{ISSUER_PUBLIC_KEY, purpose, seed_scalar};
use zns_canon::capsule::{self, CAPSULE_KEY_CONTEXT, SEED_LEN};

const CAPSULE_FILE: &str = "keys/zns_seed.capsule";

type HmacSha256 = Hmac<Sha256>;

pub fn run(args: impl Iterator<Item = String>) {
    let mut args = args;
    let command = args.next();
    let name = args.next();
    match (command.as_deref(), name) {
        (None, None) => print_public_key(),
        (Some("code"), Some(name)) => {
            if args.next().is_some() {
                usage();
            }
            println!("{:06}", code_for_name(&name));
        }
        _ => usage(),
    }
}

fn usage() -> ! {
    panic!("FATAL: usage: zns-keygen access-code | zns-keygen access-code code <name>");
}

fn print_public_key() {
    let public = access_public_key();
    println!("{}", hex::encode(public));
}

fn code_for_name(name: &str) -> u32 {
    if name.is_empty() {
        panic!("FATAL: access code name is empty");
    }
    let seed = open_seed();
    let secret = private_key_from_seed(seed.expose_secret());
    let shared = shared_secret(secret.expose_secret(), &ISSUER_PUBLIC_KEY)
        .unwrap_or_else(|error| panic!("FATAL: {error}"));
    access_code(shared.expose_secret(), name)
}

fn access_public_key() -> [u8; 32] {
    let seed = open_seed();
    let secret = private_key_from_seed(seed.expose_secret());
    public_key(secret.expose_secret())
}

/// Read the ceremony capsule and unseal the seed. The file is not modified.
fn open_seed() -> Secret<[u8; SEED_LEN]> {
    let capsule_bytes = capsule::read_capsule_file(CAPSULE_FILE)
        .unwrap_or_else(|error| panic!("FATAL: read capsule: {error}"));
    let capsule = capsule::parse_capsule(&capsule_bytes)
        .unwrap_or_else(|error| panic!("FATAL: parse capsule: {error}"));
    let sealing_key = zns_canon::sealing::derive_sealing_key(CAPSULE_KEY_CONTEXT)
        .unwrap_or_else(|error| panic!("FATAL: derive sealing key: {error}"));
    capsule::unseal_seed(&sealing_key, &capsule)
        .unwrap_or_else(|error| panic!("FATAL: unseal capsule: {error}"))
}

fn private_key_from_seed(seed: &[u8; SEED_LEN]) -> Secret<[u8; 32]> {
    Secret::new(*seed_scalar(seed))
}

fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

fn shared_secret(
    our_private: &[u8; 32],
    their_public: &[u8; 32],
) -> Result<Secret<[u8; 32]>, &'static str> {
    let ours = StaticSecret::from(*our_private);
    let shared = ours.diffie_hellman(&PublicKey::from(*their_public));
    if !shared.was_contributory() {
        return Err("X25519 shared secret is not contributory");
    }
    Ok(Secret::new(shared.to_bytes()))
}

/// The six-digit code the mint accepts for `name`.
fn access_code(shared: &[u8; 32], name: &str) -> u32 {
    let gate = purpose(shared);
    let mut digest = hmac_sha256(&*gate, name.as_bytes());
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    digest.zeroize();
    n % 1_000_000
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let mut out = mac.finalize().into_bytes();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    out.zeroize();
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn mint_judge_accepts_these_codes() {
        let key = vector_key();
        let gate = purpose(&key);
        assert_eq!(
            hex::encode(*gate),
            "5e2db6040cd32d2486675a3b3d60b9d4d96e9c8d4a5f862e0dfd7bd6a3f57b91"
        );
        assert_eq!(access_code(&key, "alice"), 352_582);
        assert_eq!(access_code(&key, "bob"), 131_624);
    }

    #[test]
    fn the_public_key_is_determined_by_the_seed() {
        let seed = [0x11; SEED_LEN];
        let private = private_key_from_seed(&seed);
        assert_eq!(
            hex::encode(private.expose_secret()),
            "cf5784abd38e10d8de32aa90525d15f4f55384dfa5e107e3f1cc265fc372509e"
        );
        assert_eq!(
            hex::encode(public_key(private.expose_secret())),
            "2a6582c9964d8908f1557412e8b8edd27e94d25126f235c84fbf01b1a8879425"
        );
    }

    #[test]
    fn issuer_and_seed_derive_the_same_code() {
        let seed = [0x22; SEED_LEN];
        let keygen = private_key_from_seed(&seed);
        let issuer = [2u8; 32];
        let keygen_public = public_key(keygen.expose_secret());
        let issuer_public = public_key(&issuer);
        let from_keygen = shared_secret(keygen.expose_secret(), &issuer_public).unwrap();
        let from_issuer = shared_secret(&issuer, &keygen_public).unwrap();
        assert_eq!(from_keygen.expose_secret(), from_issuer.expose_secret());
        assert_eq!(
            access_code(from_keygen.expose_secret(), "alice"),
            access_code(from_issuer.expose_secret(), "alice")
        );
    }

    #[test]
    fn a_low_order_public_key_is_rejected() {
        let err = shared_secret(&vector_key(), &[0u8; 32]).unwrap_err();
        assert!(err.contains("not contributory"));
    }
}
