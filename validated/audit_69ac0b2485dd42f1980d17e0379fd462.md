### Title
Missing Bitcoin Address Validation in `request_refund` Enables Griefing of Victim Deposits - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
The `request_refund` entry point accepts any arbitrary string as `refund_address` without validating it is a well-formed Bitcoin/Zcash address for the configured chain. Because only one refund request may exist per UTXO, an attacker can front-run a victim's refund submission with a syntactically invalid address, causing every subsequent `execute_refund` call to panic and permanently blocking the victim from submitting their own valid refund request until DAO/Operator intervention.

### Finding Description
In `internal_request_refund` (`contracts/satoshi-bridge/src/refund.rs`, lines 137–184), the caller-supplied `refund_address` string undergoes no format or chain-validity check. The only guard that touches `refund_address` is the equality check against `deposit_msg.refund_address` (lines 154–158), which is skipped entirely when `deposit_msg.refund_address` is `None` — the common case for standard deposits. [1](#0-0) 

The raw string is forwarded through the light-client promise and stored verbatim in `RefundRequest` inside `request_refund_callback` (lines 564–574) with no address parsing: [2](#0-1) 

Address parsing only occurs later, inside `build_refund_output`, called during `execute_refund`: [3](#0-2) 

If the stored string is not a valid address, `Address::parse(...).expect("Invalid refund address")` panics, reverting `execute_refund` every time it is called.

The duplicate-request guard in `request_refund_callback` (lines 544–547) enforces that only one refund request may exist per UTXO key: [4](#0-3) 

Combined with the panic in `build_refund_output`, this creates a permanent stuck state: the malicious request occupies the slot, `execute_refund` always panics, and the victim cannot register their own valid request.

The victim's deposit details (`deposit_msg`) are publicly observable via the `LogDepositAddress` event emitted by `get_user_deposit_address`: [5](#0-4) 

### Impact Explanation
**Medium** — Attacker-triggered temporary locking of bridged funds. The victim's BTC deposit UTXO is stuck: `execute_refund` always panics, `verify_deposit` may also be unavailable (e.g., the relayer that would call it has already failed), and the victim cannot submit a corrected refund request. Recovery requires DAO/Operator to call `reject_refund`, introducing mandatory operator intervention and a delay proportional to DAO responsiveness. This matches the allowed impact: *"attacker-triggered temporary locking of bridged funds."*

### Likelihood Explanation
**Medium** — The attacker must:
1. Monitor NEAR events for `LogDepositAddress` to learn the victim's `deposit_msg`.
2. Observe that the corresponding deposit has not been finalized via `verify_deposit`.
3. Obtain the BTC transaction bytes and inclusion proof (all public on-chain data).
4. Pay the `required_balance_for_request_refund()` storage deposit.
5. Submit `request_refund` before the victim does.

All required data is publicly available on-chain. The cost is the storage deposit (a small NEAR amount). Front-running is straightforward on NEAR where transaction ordering is observable.

### Recommendation
Validate `refund_address` as a well-formed address for the configured chain at the start of `internal_request_refund`, before dispatching the light-client promise. Specifically, call `crate::network::Address::parse(&refund_address, config.chain.clone())` and `require!` it succeeds. This mirrors the validation already performed in `build_refund_output` and `string_to_script_pubkey`: [6](#0-5) 

### Proof of Concept

1. Victim sends BTC to a deposit address derived from `deposit_msg = { recipient_id: "victim.near", refund_address: None }`. The deposit is never finalized (relayer failure, wrong metadata, etc.).
2. Attacker reads the `LogDepositAddress` NEAR event to recover `deposit_msg`, then fetches the BTC transaction bytes and constructs a valid `TxInclusionProof`.
3. Attacker calls:
   ```
   request_refund(
     deposit_msg,
     refund_address = "NOT_A_VALID_BTC_ADDRESS",
     tx_bytes,
     vout,
     proof,
     gas_fee = None
   )
   ```
   attaching the required storage deposit.
4. The light client confirms the transaction. `request_refund_callback` stores `RefundRequest { refund_address: "NOT_A_VALID_BTC_ADDRESS", ... }`.
5. Victim calls `request_refund` with a valid address → reverts: *"Refund request already exists for this UTXO"*.
6. Anyone calls `execute_refund` → `build_refund_output` calls `Address::parse("NOT_A_VALID_BTC_ADDRESS", ...)` → `.expect("Invalid refund address")` panics → transaction reverts.
7. Victim's BTC is locked until DAO calls `reject_refund`, after which the victim must re-submit and wait through the full `unsafe_refund_timelock_sec` (14 days by default). [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L294-298)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-574)
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
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L462-472)
```rust
    pub fn get_user_deposit_address(&self, deposit_msg: DepositMsg) -> String {
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path).to_string();
        Event::LogDepositAddress {
            deposit_msg,
            path,
            deposit_address: deposit_address.clone(),
        }
        .emit();
        deposit_address
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```

**File:** contracts/satoshi-bridge/src/config.rs (L168-175)
```rust
    pub fn string_to_script_pubkey(&self, address_string: &str) -> ScriptBuf {
        let chain = self.get_utxo_network();

        Address::parse(address_string, chain)
            .unwrap_or_else(|e| env::panic_str(&format!("{address_string}: {e}")))
            .script_pubkey()
            .expect("Failed to get script pubkey")
    }
```
