### Title
Corrupted `tx_bytes` Storage in `internal_safe_verify_deposit_entry` Causes Permanently Unspendable UTXOs - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary
In `internal_safe_verify_deposit_entry`, when the caller-supplied `tx_bytes` exceed 10 000 bytes, the code silently replaces them with `vec![0u8; 300]` — 300 zero bytes — before storing the UTXO on-chain. The comment calls this "truncating to 300 bytes," but it is not a truncation: the original bytes are discarded and replaced with zeros. Any UTXO deposited through the safe-deposit path with a large transaction will be stored with a completely invalid `tx_bytes` field, corrupting the on-chain UTXO record.

### Finding Description
The root cause is in `internal_safe_verify_deposit_entry`:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs  L204-L209
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]          // ← NOT a truncation; replaces with 300 zero bytes
} else {
    tx_bytes
};

let utxo = UTXO {
    path,
    tx_bytes,               // ← zeroed bytes stored permanently
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
``` [1](#0-0) 

The `transaction` object is decoded from the **original** `tx_bytes` before this block (line 191), so the deposit amount and script-pubkey checks pass correctly. But the UTXO that is persisted on-chain carries `tx_bytes = [0u8; 300]`.

The analog to the Buffer report is direct: the Buffer bug had an **extra term** (`buf.buf.length`) in a condition that triggered unnecessary resizing even when capacity was sufficient. Here, the extra condition branch (`tx_bytes.len() > 10000`) triggers an incorrect replacement instead of a proper rejection or truncation, corrupting stored state in a way that is invisible to the caller.

The non-safe deposit path (`internal_verify_deposit_entry`, lines 117–169) has **no such truncation** and stores `tx_bytes` verbatim:

```rust
// L145-L150
let utxo = UTXO {
    path,
    tx_bytes,   // original bytes, unmodified
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
``` [2](#0-1) 

The `UTXO.tx_bytes` field is carried through the entire withdrawal pipeline. In `remove_vutxo_by_psbt` the UTXO is lifted into a `VUTXO` and stored inside `BTCPendingInfo.vutxos`: [3](#0-2) 

For legacy (non-segwit) Bitcoin inputs the full previous-transaction bytes are required by the signing layer (`chain_signature.rs`) to construct the sighash. Zeroed bytes will produce an invalid sighash, causing the MPC signing step to produce a signature over garbage data, and the resulting transaction will be rejected by the Bitcoin network. Even for segwit inputs, downstream code that decodes `tx_bytes` to reconstruct the outpoint or verify the deposit will panic or produce wrong results.

The refund path is **not** affected because `RefundRequest` stores its own independent `tx_bytes` supplied at `request_refund` time, not the UTXO's field: [4](#0-3) 

### Impact Explanation
After a safe deposit with `tx_bytes.len() > 10 000`, the bridge mints nBTC to the user (the deposit is verified and accepted), but the stored UTXO has zeroed `tx_bytes`. When the bridge later attempts to spend that UTXO in a withdrawal or active-management PSBT, the signing step operates on corrupted data. The signed transaction is invalid and will never confirm on Bitcoin. The BTC is permanently locked in the deposit address with no recovery path short of operator intervention (and even then, the on-chain UTXO record cannot be corrected without a contract upgrade). This matches the **Medium** impact class: stuck bridge state requiring operator intervention, with potential escalation to Critical (permanent loss of user funds) if the corrupted UTXO cannot be recovered.

### Likelihood Explanation
A Bitcoin transaction exceeds 10 000 bytes when it has roughly 67+ P2PKH inputs (~148 bytes each) or 40+ P2WPKH inputs (~250 bytes each). Consolidation transactions or deposits from wallets with many small UTXOs can reach this size. Any unprivileged user who calls `safe_verify_deposit` (the public API backed by `internal_safe_verify_deposit_entry`) with such a transaction triggers the bug. No special role or key is required.

### Recommendation
Remove the truncation branch entirely. If oversized transactions must be rejected, add an explicit `require!` before decoding:

```rust
require!(
    tx_bytes.len() <= MAX_SAFE_DEPOSIT_TX_BYTES,
    "tx_bytes too large for safe deposit"
);
```

Mirror the pattern already used in the refund path (`MAX_REQUEST_REFUND_TX_BYTES` / `require!` at the entry point) so the caller receives a clear error rather than silent data corruption.

### Proof of Concept
1. Construct a Bitcoin transaction with ≥ 68 P2PKH inputs (total serialized size > 10 000 bytes) paying to the user's safe-deposit address.
2. Call `safe_verify_deposit` with this transaction and a valid Merkle proof.
3. The light-client verification passes; `internal_safe_verify_deposit_entry` decodes the transaction correctly, verifies the output, then replaces `tx_bytes` with `vec![0u8; 300]`.
4. `safe_mint_callback` stores the UTXO with zeroed `tx_bytes`; nBTC is minted to the user.
5. Any subsequent withdrawal PSBT that selects this UTXO will have `vutxos[i].tx_bytes == [0u8; 300]`. The MPC signing layer receives a zeroed previous-transaction field, produces a signature over an invalid sighash, and the broadcast transaction is rejected by the Bitcoin network. The UTXO is permanently unspendable.

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L145-150)
```rust
        let utxo = UTXO {
            path,
            tx_bytes,
            vout,
            balance: transaction.output()[vout].value.to_sat(),
        };
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L204-216)
```rust
        let tx_bytes = if tx_bytes.len() > 10000 {
            env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
            vec![0u8; 300]
        } else {
            tx_bytes
        };

        let utxo = UTXO {
            path,
            tx_bytes,
            vout,
            balance: transaction.output()[vout].value.to_sat(),
        };
```

**File:** contracts/satoshi-bridge/src/utxo.rs (L61-77)
```rust
    pub fn remove_vutxo_by_psbt(&mut self, psbt: &PsbtWrapper) -> (Vec<String>, Vec<VUTXO>) {
        let mut utxo_storage_keys = vec![];
        let vutxos = psbt
            .get_utxo_storage_keys()
            .into_iter()
            .map(|utxo_storage_key| {
                utxo_storage_keys.push(utxo_storage_key.clone());
                self.data_mut()
                    .utxos
                    .remove(&utxo_storage_key)
                    .unwrap_or_else(|| {
                        env::panic_str(&format!("UTXO {} not exist", utxo_storage_key))
                    })
            })
            .collect::<Vec<_>>();
        (utxo_storage_keys, vutxos)
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L17-26)
```rust
/// Upper bound on the deposit `tx_bytes` accepted by `request_refund`.
///
/// The RefundRequest stores `tx_bytes` verbatim (no truncation — `execute_refund`
/// later decodes them to rebuild the refund tx), so storage grows ~1:1 with tx size:
/// at this cap a request stores ~200 KB ≈ 2 NEAR, which `required_balance_for_request_refund`
/// is sized to cover. The cap also sits safely below the hard gas ceiling: decoding +
/// borsh-storing the tx happens in `request_refund_callback` (only 20 Tgas), which runs
/// out of gas around ~250 KB regardless of the attached deposit. 200 KB is ~1350 signed
/// P2PKH inputs — far above any real deposit (1-2 inputs), incl. large consolidations.
pub(crate) const MAX_REQUEST_REFUND_TX_BYTES: usize = 200_000;
```
