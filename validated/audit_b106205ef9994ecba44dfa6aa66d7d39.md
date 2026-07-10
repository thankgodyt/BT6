### Title
Wrong Amount Used for Confirmation-Count Lookup in Refund Finalization - (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary

`internal_verify_refund_finalize` passes `btc_pending_info.actual_received_amount` (the refund amount, i.e. deposit minus gas fee) to `get_confirmations`, while every other inclusion-proof path passes the full deposit amount. This is a direct analog of the FrxETHOracle bug: the wrong value is substituted into a critical security lookup, causing the bridge to enforce a lower confirmation threshold than the deposit's value warrants.

### Finding Description

In `internal_request_refund`, the full deposit output value is correctly used to determine the required confirmation count before the Light Client call: [1](#0-0) 

```rust
let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
let confirmations = self.get_confirmations(config, deposit_amount);
```

However, in `internal_verify_refund_finalize`, the confirmation count is derived from `actual_received_amount` — the refund amount after the gas fee has been subtracted — not from the original deposit amount: [2](#0-1) 

```rust
let confirmations = self.get_confirmations(config, btc_pending_info.actual_received_amount);
```

`actual_received_amount` is set in `finalize_refund_with_psbt` as `refund_amount = deposit_amount - gas_fee`: [3](#0-2) 

The `get_confirmations` strategy maps satoshi thresholds to confirmation counts — larger amounts require more confirmations: [4](#0-3) 

Because `actual_received_amount` is always strictly less than the deposit amount, whenever the deposit amount sits just above a tier boundary and the gas fee is large enough to push the refund amount below that boundary, `verify_refund_finalize` enforces fewer confirmations than the deposit's value requires.

The full deposit amount is not stored directly in `BTCPendingInfo` for refunds (`transfer_amount` is set to `0`); it would need to be reconstructed as `actual_received_amount + gas_fee`: [5](#0-4) 

### Impact Explanation

If the refund finalization is accepted with fewer confirmations than the deposit amount warrants, the bridge cleans up all state (removes the refund request and the `BTCPendingInfo`) while the refund transaction may still be at risk of a natural Bitcoin reorganization. After `verify_refund_finalize_callback` runs:

- The refund request is deleted — `execute_refund` cannot be called again.
- The deposit UTXO remains in `verified_deposit_utxo` — `verify_deposit` is permanently blocked.
- If the refund transaction is then reorganized out of the chain, the user's BTC is permanently unrecoverable through the bridge. [6](#0-5) 

This matches the **Medium** impact class: bypass of bridge confirmation policy with a realistic path to permanent locking of user funds.

### Likelihood Explanation

The bug is always present — `actual_received_amount` is always used instead of the deposit amount. Exploitation requires two conditions:

1. The deposit amount sits just above a confirmation-tier boundary while the gas fee is large enough to push the refund amount below it (e.g., deposit = 1,000,001 sat, gas fee = 2 sat, tier boundary = 1,000,000 sat).
2. A natural Bitcoin reorganization of the depth equal to the reduced confirmation count occurs before the transaction is more deeply buried.

Condition 1 is fully attacker-controllable (the user chooses the deposit amount). Condition 2 is a natural Bitcoin network event, not a 51% attack. Short reorganizations (1–3 blocks) occur occasionally on mainnet.

### Recommendation

Replace `btc_pending_info.actual_received_amount` with the full deposit amount in `internal_verify_refund_finalize`. Since `BTCPendingInfo` stores both `actual_received_amount` and `gas_fee` for refunds, the deposit amount can be reconstructed as:

```rust
let deposit_amount = btc_pending_info.actual_received_amount + btc_pending_info.gas_fee;
let confirmations = self.get_confirmations(config, deposit_amount);
```

This mirrors the correct behavior in `internal_request_refund` and ensures the finalization confirmation threshold is consistent with the deposit verification threshold.

### Proof of Concept

1. Configure `confirmations_strategy` with two tiers: `{ "1000000": 3, "9999999999": 6 }`.
2. User deposits exactly `1_000_001` satoshis → `request_refund` correctly requires 6 confirmations.
3. `execute_refund` runs with `gas_fee = 2` → `actual_received_amount = 999_999`.
4. Relayer calls `verify_refund_finalize` with a proof of only 3 confirmations.
5. `internal_verify_refund_finalize` calls `get_confirmations(config, 999_999)` → returns 3 → the Light Client call succeeds.
6. `verify_refund_finalize_callback` removes the refund request and pending info.
7. A 3-block Bitcoin reorganization invalidates the refund transaction; the user's 1,000,001-satoshi UTXO is permanently locked. [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L167-168)
```rust
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);
```

**File:** contracts/satoshi-bridge/src/refund.rs (L280-283)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L344-352)
```rust
        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount: refund_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: 0,
            psbt_hex,
```

**File:** contracts/satoshi-bridge/src/refund.rs (L434-456)
```rust
    pub(crate) fn internal_verify_refund_finalize(
        &self,
        tx_id: String,
        proof: TxInclusionProof,
        btc_pending_info: &BTCPendingInfo,
    ) -> Promise {
        let config = self.internal_config();
        let confirmations = self.get_confirmations(config, btc_pending_info.actual_received_amount);
        self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            tx_id.clone(),
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
            confirmations,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_VERIFY_REFUND_CALLBACK)
                .verify_refund_finalize_callback(tx_id),
        )
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L483-491)
```rust
        self.data_mut()
            .refund_requests
            .remove(&utxo_storage_keys[0]);

        // Clean up: remove pending info
        self.internal_remove_btc_pending_info(&tx_id);
        self.internal_unwrap_mut_account(&account_id)
            .btc_pending_verify_list
            .remove(&tx_id);
```

**File:** contracts/satoshi-bridge/src/config.rs (L196-220)
```rust
    pub fn get_confirmations(&self, satoshi_amount: u128) -> u64 {
        require!(
            !self.confirmations_strategy.is_empty(),
            "confirmations_strategy is empty"
        );
        // The key is constrained to U64 during assignment, so it won't panic.
        let mut keys = self
            .confirmations_strategy
            .keys()
            .map(|k| k.parse::<u128>().unwrap())
            .collect::<Vec<_>>();
        keys.sort_unstable();
        for key in &keys {
            if *key > satoshi_amount {
                return u64::from(*self.confirmations_strategy.get(&key.to_string()).unwrap());
            }
        }
        let max_key = keys.last().unwrap();
        u64::from(
            *self
                .confirmations_strategy
                .get(&max_key.to_string())
                .unwrap(),
        )
    }
```
