//! Zebra JSON-RPC client.

use serde::{Deserialize, Serialize};
use zcash_protocol::consensus::BlockHeight;

#[cfg(not(feature = "testnet"))]
const RPC_URL: &str = "http://127.0.0.1:8232";
#[cfg(feature = "testnet")]
const RPC_URL: &str = "http://127.0.0.1:18232";

/// Stateless JSON-RPC transport.
pub struct Rpc;

impl Rpc {
    fn call<M, P, R>(method: M, params: P) -> Result<R, String>
    where
        M: Into<String>,
        P: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method.into(),
            "params": params,
            "id": 0,
        });
        let mut request = ureq::post(RPC_URL)
            .set("content-type", "application/json")
            .timeout(std::time::Duration::from_secs(10));
        if let Some(authorization) = cookie_header() {
            request = request.set("authorization", &authorization);
        }
        let resp = request
            .send_json(serde_json::to_value(&body).expect("FATAL: encode RPC request"))
            .map_err(|e| format!("RPC transport: {e}"))?;
        let parsed: RpcResp<R> = resp.into_json().map_err(|e| format!("RPC decode: {e}"))?;
        match parsed {
            RpcResp {
                result: Some(r),
                error: None,
            } => Ok(r),
            RpcResp { error: Some(e), .. } => Err(format!("RPC error: {e}")),
            _ => Err("RPC returned null".into()),
        }
    }

    /// Chain tip height + hash.
    pub fn tip() -> Result<(BlockHeight, String), String> {
        let info: BlockchainInfo = Self::call("getblockchaininfo", serde_json::json!({}))?;
        Ok((BlockHeight::from_u32(info.blocks), info.best_block_hash))
    }

    /// UTXOs for a transparent address.
    pub fn address_utxos(addr: &str) -> Result<Vec<AddressUtxo>, String> {
        Self::call(
            "getaddressutxos",
            serde_json::json!([{"addresses": [addr]}]),
        )
    }

    /// Broadcast raw tx hex.
    pub fn send_raw(hex: &str) -> Result<String, String> {
        Self::call("sendrawtransaction", serde_json::json!([hex]))
    }

    /// Whether `txid` is already in the mempool or chain.
    ///
    /// A missing-transaction RPC error is `Absent`. Any other failure is
    /// returned so the caller does not broadcast when the node cannot be asked.
    pub fn transaction_presence(txid: &str) -> Result<TxLookup, String> {
        match Self::call::<_, _, serde_json::Value>(
            "getrawtransaction",
            serde_json::json!([txid, 1]),
        ) {
            Ok(value) => {
                let (height, block_hash) = transaction_position(&value);
                Ok(TxLookup::Found { height, block_hash })
            }
            Err(message) if transaction_is_absent(&message) => Ok(TxLookup::Absent),
            Err(message) => Err(message),
        }
    }
}

/// Result of looking up one transaction id.
pub enum TxLookup {
    Absent,
    /// `height` is missing in the mempool and negative on a side chain.
    /// `block_hash` is missing until the transaction is in a block.
    Found {
        height: Option<i64>,
        block_hash: Option<String>,
    },
}

/// The node has to serve this block. The same pins the mint uses.
fn pinned() -> (u32, &'static str) {
    #[cfg(feature = "testnet")]
    {
        (
            4_238_000,
            "0017b69a52b06033149cbb86f89488e7cfc525b3e5e98561a51b6ca271a0576e",
        )
    }
    #[cfg(not(feature = "testnet"))]
    {
        (
            3_353_606,
            "00000000008b5211479a54c24191ff237efa3d39bb28b1cc696195eeff5e5605",
        )
    }
}

impl Rpc {
    /// Refuses a node whose block at the pinned height is not the pinned hash.
    pub fn pinned_block_ok() -> Result<(), String> {
        let (height, expected) = pinned();
        let actual = Self::block_hash(height)?;
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(format!("block {height} is not the pinned block"));
        }
        Ok(())
    }

    /// Display hash of the block at `height`.
    pub fn block_hash(height: u32) -> Result<String, String> {
        Self::call("getblockhash", serde_json::json!([height]))
    }

    /// `true` when `depth - 1` previous-hash links from `tip_hash` land on `inclusion_hash`.
    pub fn inclusion_under_tip(
        tip_hash: &str,
        inclusion_hash: &str,
        depth: u32,
    ) -> Result<bool, String> {
        if depth == 0 {
            return Ok(false);
        }
        let mut current = tip_hash.to_string();
        for _ in 1..depth {
            current = Self::previous_hash(&current)?;
        }
        Ok(current.eq_ignore_ascii_case(inclusion_hash))
    }

    fn previous_hash(hash: &str) -> Result<String, String> {
        let header: serde_json::Value =
            Self::call("getblockheader", serde_json::json!([hash, true]))?;
        header
            .get("previousblockhash")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "block header has no previous hash".to_string())
    }
}

/// Height and block hash from a verbose transaction object.
///
/// A negative height is a side chain and is preserved.
pub(crate) fn transaction_position(value: &serde_json::Value) -> (Option<i64>, Option<String>) {
    let height = value.get("height").and_then(serde_json::Value::as_i64);
    let block_hash = value
        .get("blockhash")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    (height, block_hash)
}

/// HTTP basic auth for Zebra's cookie file, when that file exists.
fn cookie_header() -> Option<String> {
    let path =
        std::env::var("ZEBRA_COOKIE_FILE").unwrap_or_else(|_| "/var/lib/zebra/.cookie".to_string());
    let raw = std::fs::read_to_string(path).ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let pair = if raw.contains(':') {
        raw.to_string()
    } else {
        format!("__cookie__:{raw}")
    };
    Some(format!("Basic {}", base64(&pair)))
}

fn base64(input: &str) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let chunk = ((bytes[index] as u32) << 16)
            | ((bytes[index + 1] as u32) << 8)
            | (bytes[index + 2] as u32);
        out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 6) & 63) as usize] as char);
        out.push(TABLE[(chunk & 63) as usize] as char);
        index += 3;
    }
    match bytes.len() - index {
        1 => {
            let chunk = (bytes[index] as u32) << 16;
            out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
            out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let chunk = ((bytes[index] as u32) << 16) | ((bytes[index + 1] as u32) << 8);
            out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
            out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
            out.push(TABLE[((chunk >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// True only for the RPC error Zebra and zcashd use when a txid is unknown.
///
/// Other failures, including a missing RPC method, must not look like absence.
pub(crate) fn transaction_is_absent(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("no such mempool")
        || lower.contains("no such transaction")
        || lower.contains("no information available about transaction")
        || lower.contains("transaction not found in mempool or best chain")
}

/// True when Zebra rejected the stored anchor because its expiry height passed.
pub(crate) fn transaction_is_expired(error: &str) -> bool {
    error
        .to_ascii_lowercase()
        .contains("greater than its expiry")
}

#[derive(Deserialize)]
struct RpcResp<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    message: String,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Deserialize)]
struct BlockchainInfo {
    blocks: u32,
    #[serde(rename = "bestblockhash")]
    best_block_hash: String,
}

/// UTXO from getaddressutxos.
#[derive(Deserialize)]
pub struct AddressUtxo {
    pub txid: String,
    #[serde(rename = "outputIndex")]
    pub output_index: u32,
    pub satoshis: u64,
    pub script: String,
}

#[cfg(test)]
mod tests {
    use super::{base64, transaction_is_absent, transaction_is_expired, transaction_position};

    #[test]
    fn only_a_missing_transaction_counts_as_absent() {
        assert!(transaction_is_absent(
            "RPC error: No such mempool or blockchain transaction"
        ));
        assert!(transaction_is_absent(
            "RPC error: No information available about transaction"
        ));
        assert!(transaction_is_absent(
            "RPC error: Transaction not found in mempool or best chain"
        ));
        assert!(!transaction_is_absent("RPC error: Method not found"));
        assert!(!transaction_is_absent("RPC transport: connection refused"));
        assert!(!transaction_is_absent(
            "RPC error: transaction already in block chain"
        ));
    }

    #[test]
    fn transaction_position_keeps_side_chain_and_mempool() {
        assert_eq!(
            transaction_position(&serde_json::json!({"height": -1, "confirmations": 100})),
            (Some(-1), None)
        );
        assert_eq!(
            transaction_position(&serde_json::json!({"hex": "00", "confirmations": 10})),
            (None, None)
        );
        assert_eq!(
            transaction_position(
                &serde_json::json!({"height": 4408922, "confirmations": 10, "blockhash": "aa"})
            ),
            (Some(4408922), Some("aa".to_string()))
        );
    }

    #[test]
    fn cookie_basic_auth_uses_the_cookie_user() {
        assert_eq!(base64("__cookie__:ab"), "X19jb29raWVfXzphYg==");
    }

    #[test]
    fn only_an_expiry_rejection_rebuilds_the_anchor() {
        assert!(transaction_is_expired(
            "RPC error: transaction is greater than its expiry"
        ));
        assert!(!transaction_is_expired(
            "RPC error: transaction already in block chain"
        ));
        assert!(!transaction_is_expired("RPC transport: connection refused"));
    }
}
