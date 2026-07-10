### Title
Unvalidated `refund_address` Causes Permanent Panic in `build_refund_output` via `.expect()`, Locking Refund UTXO — (`contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/network.rs`)

---

### Summary

`request_refund` is publicly callable (no method-level `#[trusted_relayer]` guard) and stores `refund_address` verbatim without validating it as a parseable address for the configured chain. When `execute_refund` is later called, `build_refund_output` calls `Address::parse` on the stored address and uses `.expect("Invalid refund address")`, which panics if the address is invalid (e.g., a Zcash Regtest address submitted to a Mainnet/Testnet chain). The panic reverts the callback but leaves the refund request in storage, permanently blocking `execute_refund` for that UTXO until DAO/Operator intervention.

---

### Finding Description

**Step 1 — Public entrypoint with no address validation.**

`request_refund` in the second `#[trusted_relayer] #[near] impl Contract` block in `api/bridge.rs` carries only `#[payable]` and `#[pause]` at the method level — no method-level `#[trusted_relayer]` attribute. The impl-level `#[trusted_relayer]` is a configuration marker (it has no parameters, unlike the main `impl Contract` block at `lib.rs:175–179` which carries `bypass_roles`, `manager_roles`, `config_roles`). Methods that actually require a trusted relayer — `verify_refund_finalize`, `remove_refund_pending_tx_id` — carry the attribute explicitly at the method level. `request_refund` and `execute_refund` do not. [1](#0-0) [2](#0-1) 

**Step 2 — `refund_address` stored without validation.**

`internal_request_refund` checks that `refund_address == deposit_msg.refund_address` when the latter is set, but performs no syntactic or chain-specific validation of the address string itself. The raw string is stored in `RefundRequest.refund_address`. [3](#0-2) [4](#0-3) 

**Step 3 — `.expect()` on `Address::parse` in `build_refund_output`.**

`build_refund_output` calls `Address::parse` and immediately panics on `Err`: [5](#0-4) 

**Step 4 — `Address::parse` returns `Err` for a Regtest address on Mainnet/Testnet.**

For `ZcashMainnet`/`ZcashTestnet`, `Address::parse` calls `ZcashAddress::try_from_encoded` (which succeeds for a Regtest-encoded address), then `convert_if_network::<Self>(NetworkType::Main)`. This invokes `try_from_transparent_p2pkh` (or equivalent) with `NetworkType::Regtest`, which calls `zcash_chain_from_network(NetworkType::Regtest)` → `Err("Regtest network not supported")`. `Address::parse` returns `Err`, and `.expect()` panics. [6](#0-5) [7](#0-6) 

**Step 5 — Panic in `execute_refund_callback` leaves request stuck.**

On the Zcash path, `execute_refund` dispatches to `execute_refund_callback` (`#[private]`). The panic inside the callback reverts only the callback, not the original call. The refund request remains in storage with `executed = false`. Every subsequent `execute_refund` call for the same UTXO re-enters the same panic path. [8](#0-7) 

---

### Impact Explanation

An attacker can front-run a victim's legitimate refund request (since `request_refund` has no ownership check — any caller can submit a request for any UTXO) by submitting a Regtest address. The victim's deposit UTXO is then stuck: `execute_refund` always panics, and the UTXO cannot be refunded without DAO/Operator rejecting the poisoned request and creating a new one. This constitutes attacker-triggered temporary locking of bridged funds requiring operator intervention.

---

### Likelihood Explanation

- `request_refund` is publicly callable with no role gate.
- Deposit UTXOs are visible on-chain; an attacker can identify any pending unfinalized deposit.
- Submitting a Regtest address requires no special knowledge — Regtest address formats are documented.
- The attack requires only a valid light-client proof for the target UTXO (publicly available on-chain data) and the attached storage deposit.

---

### Recommendation

Validate `refund_address` against the configured chain at `request_refund` time (inside `request_refund_callback`, after the light-client proof is confirmed) by calling `Address::parse` and returning an error if it fails. Replace the `.expect()` in `build_refund_output` with proper error propagation so a bad address causes a graceful `require!` failure rather than a panic.

---

### Proof of Concept

```
1. Bridge is deployed on ZcashMainnet.
2. Victim deposits ZEC; deposit UTXO = txid@0 is visible on-chain.
3. Attacker calls request_refund(
       deposit_msg = <victim's deposit_msg with refund_address: None>,
       refund_address = "<valid Zcash Regtest address, e.g. zregtestsapling1...>",
       tx_bytes = <victim's deposit tx>,
       vout = 0,
       proof = <valid light-client proof>,
       gas_fee = None
   ) with attached storage deposit.
4. request_refund_callback stores RefundRequest { refund_address: "<regtest addr>", ... }.
5. After timelock, anyone calls execute_refund("txid@0", None).
6. execute_refund_callback calls build_refund_output("<regtest addr>", amount).
7. Address::parse("<regtest addr>", ZcashMainnet):
   - ZcashAddress::try_from_encoded succeeds (Regtest address is valid bech32m).
   - convert_if_network(NetworkType::Main) → try_from_transparent_p2pkh(Regtest, ...) 
     → zcash_chain_from_network(Regtest) → Err.
   - Address::parse returns Err.
8. .expect("Invalid refund address") panics.
9. Callback reverts; refund request remains in storage.
10. Steps 5–9 repeat indefinitely. UTXO is stuck until DAO rejects the request.
```

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L480-535)
```rust
#[trusted_relayer]
#[near]
impl Contract {
    // ── Refund API ──

    /// Submit a refund request for a deposit that was never finalized via `verify_deposit` or `safe_verify_deposit`.
    /// The BTC transaction is verified through the Light Client to prove the deposit exists.
    /// After the timelock period, anyone can call `execute_refund` to initiate the return.
    ///
    /// Requires an attached deposit of at least `required_balance_for_request_refund()`.
    /// The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee.
    ///
    /// # Arguments
    ///
    /// * `deposit_msg` - The original deposit message. If `deposit_msg.refund_address` is set,
    ///   it must match the provided `refund_address`.
    /// * `refund_address` - BTC address to send the refund to. If `deposit_msg.refund_address`
    ///   is `None`, this value is used directly.
    /// * `tx_bytes` - BTC transaction bytes proving the deposit.
    /// * `vout` - Output index of the deposit in the transaction.
    /// * `proof` - Transaction inclusion proof for Light Client verification, bundling:
    ///   `tx_block_blockhash` (block hash containing the transaction), `tx_index`
    ///   (transaction index within the block), `merkle_proof` (Merkle proof of the
    ///   transaction), and the coinbase fields `coinbase_tx_id` and
    ///   `coinbase_merkle_proof` used to verify the block's coinbase.
    /// * `gas_fee` - Optional custom gas fee. Only DAO or Operator can set this.
    ///   If `None`, the default `config.max_btc_gas_fee` is used during `execute_refund`.
    #[allow(clippy::too_many_arguments)]
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
        if gas_fee.is_some() {
            let caller = env::predecessor_account_id();
            require!(
                self.acl_has_role(Role::DAO.into(), caller.clone())
                    || self.acl_has_role(Role::Operator.into(), caller),
                "Only DAO or Operator can specify custom gas_fee"
            );
        }
        self.internal_request_refund(
            deposit_msg,
            refund_address,
            tx_bytes,
            vout,
            proof,
            gas_fee.map(|v| v.0),
        )
    }
```

**File:** contracts/satoshi-bridge/src/lib.rs (L175-179)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L294-308)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
        TxOut {
            value: Amount::from_sat(
                u64::try_from(refund_amount)
                    .unwrap_or_else(|_| env::panic_str("Refund amount overflow")),
            ),
            script_pubkey: refund_script_pubkey,
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-578)
```rust
        let refund_request = RefundRequest {
            deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
            utxo_storage_key: utxo_storage_key.clone(),
            tx_bytes,
            vout,
            amount,
            refund_address,
            gas_fee: resolved_gas_fee,
            created_at_sec: nano_to_sec(env::block_timestamp()),
            executed: false,
        };

        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/network.rs (L88-98)
```rust
fn zcash_chain_from_network(
    net: zcash_protocol::consensus::NetworkType,
) -> Result<Chain, ConversionError<String>> {
    match net {
        zcash_protocol::consensus::NetworkType::Main => Ok(Chain::ZcashMainnet),
        zcash_protocol::consensus::NetworkType::Test => Ok(Chain::ZcashTestnet),
        zcash_protocol::consensus::NetworkType::Regtest => {
            Err("Regtest network not supported".to_string().into())
        }
    }
}
```

**File:** contracts/satoshi-bridge/src/network.rs (L152-166)
```rust
    pub fn parse(address: &str, chain: Chain) -> Result<Self, String> {
        if chain == Chain::ZcashMainnet || chain == Chain::ZcashTestnet {
            let addr = ZcashAddress::try_from_encoded(address)
                .map_err(|e| format!("Error on parsing ZCash Address: {e}"))?;

            let network = match chain {
                Chain::ZcashMainnet => zcash_protocol::consensus::NetworkType::Main,
                Chain::ZcashTestnet => zcash_protocol::consensus::NetworkType::Test,
                _ => unreachable!(),
            };

            return addr
                .convert_if_network::<Self>(network)
                .map_err(|e| e.to_string());
        }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L99-105)
```rust
        // Shielded refund routes funds through the Orchard bundle (no transparent
        // output); transparent refund pays a single t-address output.
        let output = if orchard_bundle.is_some() {
            Vec::new()
        } else {
            vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
        };
```
