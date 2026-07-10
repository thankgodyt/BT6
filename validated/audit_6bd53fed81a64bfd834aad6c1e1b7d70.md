### Title
Sub-minimum deposit via `unavailable_utxo_callback` permanently blocks `request_refund` by inserting into `verified_deposit_utxo` — (`contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary

When a BTC deposit below `min_deposit_amount` is processed, `internal_verify_deposit` routes the callback to `unavailable_utxo_callback`, which inserts the UTXO's storage key into `verified_deposit_utxo`. Subsequently, `request_refund_callback` unconditionally rejects any refund for that same UTXO because `verified_deposit_utxo.contains()` returns `true`. No other on-chain recovery path exists, permanently locking the user's BTC.

### Finding Description

**Step 1 — Sub-minimum routing in `internal_verify_deposit`:**

In `internal_verify_deposit`, when `deposit_amount < config.min_deposit_amount`, the callback is routed to `unavailable_utxo_callback`: [1](#0-0) 

**Step 2 — `unavailable_utxo_callback` inserts into `verified_deposit_utxo`:**

`unavailable_utxo_callback` unconditionally inserts the UTXO key into `verified_deposit_utxo` and stores the UTXO in `unavailable_utxos`. No nBTC is minted. [2](#0-1) 

**Step 3 — `request_refund_callback` is permanently blocked:**

`request_refund_callback` checks `verified_deposit_utxo.contains()` and panics with `"UTXO already verified via deposit"` if the key is present — regardless of whether the UTXO was processed via a normal deposit or via `unavailable_utxo_callback`: [3](#0-2) 

**Step 4 — No other recovery path:**

The `load_refund_request_for_execute` guard (used by `execute_refund`) also checks `verified_deposit_utxo`, but it only bypasses the check when `refund_request.executed == true`: [4](#0-3) 

Since `request_refund_callback` is blocked before a `RefundRequest` is ever stored, `execute_refund` can never be reached. The UTXO sits in `unavailable_utxos` indefinitely with no mint, no refund, and no removal mechanism.

**Access control note:**

`verify_deposit` and `verify_deposit_v2` are gated by `#[trusted_relayer]`: [5](#0-4) 

An unprivileged user cannot call `verify_deposit` directly. However, the trusted relayer calls it as part of normal bridge operation for every confirmed deposit, including sub-minimum ones. The vulnerability is therefore triggered by the bridge's own standard processing flow, not by a direct attacker call. `request_refund` is in the same `#[trusted_relayer]` impl block but carries no individual `#[trusted_relayer]` attribute and is callable by any user: [6](#0-5) 

### Impact Explanation

Any BTC sent below `min_deposit_amount` to a bridge deposit address is permanently locked:
- No nBTC is minted (deposit is sub-minimum).
- `verified_deposit_utxo` is marked, blocking `request_refund_callback`.
- `unavailable_utxos` has no user-facing withdrawal or refund mechanism.
- The funds are irrecoverable without a contract upgrade.

This matches **Critical — significant permanent locking of user funds**.

### Likelihood Explanation

Sub-minimum deposits are a realistic occurrence (user error, dust, fee miscalculation). The trusted relayer processes them automatically. The locking is deterministic and immediate once `unavailable_utxo_callback` completes. No special attacker capability is required beyond sending a small BTC amount to a valid deposit address.

### Recommendation

`unavailable_utxo_callback` should **not** insert into `verified_deposit_utxo`. The purpose of `verified_deposit_utxo` is replay protection for successful deposits. Sub-minimum UTXOs have not been successfully deposited and must remain eligible for refund. Either:
1. Remove the `verified_deposit_utxo.insert(...)` call from `unavailable_utxo_callback`, or
2. Add a separate set (e.g., `unavailable_deposit_utxo`) for replay protection of sub-minimum deposits, and exclude it from the `request_refund_callback` guard.

### Proof of Concept

1. User sends `min_deposit_amount - 1` satoshis to their bridge deposit address.
2. Trusted relayer calls `verify_deposit_v2` with the confirmed transaction.
3. `internal_verify_deposit` routes to `unavailable_utxo_callback` (line 45–50).
4. `unavailable_utxo_callback` inserts `utxo_storage_key` into `verified_deposit_utxo` (line 307–311).
5. User calls `request_refund` with the same transaction.
6. `request_refund_callback` hits `require!(!verified_deposit_utxo.contains(...), "UTXO already verified via deposit")` → panics (line 535–541).
7. No `RefundRequest` is stored; `execute_refund` is unreachable.
8. BTC is permanently locked in `unavailable_utxos` with no recovery path.

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L45-50)
```rust
        if deposit_amount < config.min_deposit_amount {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_UNAVAILABLE_UTXO_CALL_BACK)
                    .unavailable_utxo_callback(recipient_id, pending_utxo_info),
            )
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L306-316)
```rust
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );
        let deposit_amount = u128::from(pending_utxo_info.utxo.balance);
        self.internal_set_unavailable_utxo(
            &pending_utxo_info.utxo_storage_key,
            pending_utxo_info.utxo,
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L534-541)
```rust
        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L26-47)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    #[deprecated(note = "use verify_deposit_v2")]
    pub fn verify_deposit(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Vec<u8>,
        vout: usize,
        tx_block_blockhash: String,
        tx_index: u64,
        merkle_proof: Vec<String>,
    ) -> Promise {
        self.internal_verify_deposit_entry(
            deposit_msg,
            tx_bytes,
            vout,
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            None,
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
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
