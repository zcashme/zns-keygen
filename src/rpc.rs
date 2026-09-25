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
        let resp = ureq::post(RPC_URL)
            .set("content-type", "application/json")
            .timeout(std::time::Duration::from_secs(10))
            .send_json(serde_json::to_value(&body).unwrap())
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
