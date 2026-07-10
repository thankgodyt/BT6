### Title
`refund_timelock_sec == unsafe_refund_timelock_sec` Eliminates DAO Review Window for Unsafe Refund Requests — (File: `contracts/satoshi-bridge/src/config.rs`)

---

### Summary

`Config::assert_valid()` uses `<=` when comparing `refund_timelock_sec` and `unsafe_refund_timelock_sec`, permitting them to be equal. The `unsafe_refund_timelock_sec` path is the **sole protection** giving the DAO time to reject refund requests where the caller supplies an arbitrary refund address (i.e., `deposit_msg.refund_address` is `None`). When the two timelocks are equal, that extra review window vanishes entirely, and an attacker who submits a refund request for another user's unverified deposit — redirecting it to their own BTC address — faces no longer a review window than a pre-authorized refund.

---

### Finding Description

**Root cause — `config.rs` line 154–157:**

```rust
require!(
    self.refund_timelock_sec <= self.unsafe_refund_timelock_sec,
    "refund_timelock_sec must be <= unsafe_refund_timelock_sec"
);
```

The `<=` operator allows `refund_timelock_sec == unsafe_refund_timelock_sec`. No lower-bound check on either value is enforced, so both may also be set to `0`.

**Runtime enforcement — `refund.rs` lines 216–227:**

```rust
if refund_request.deposit_msg().refund_address.is_some() {
    if is_privileged { 0 } else { config.refund_timelock_sec }
} else {
    // Refund address supplied by caller: longer timelock to give DAO time to reject.
    config.unsafe_refund_timelock_sec
}
```

When `refund_timelock_sec == unsafe_refund_timelock_sec`, both branches resolve to the same duration. The comment's stated intent ("longer timelock") is silently violated.

**Attacker-controlled entry path — `refund.rs` `internal_request_refund` (lines 137–184):**

`request_refund` is a public, permissionless call. Any NEAR account can submit a refund request for any on-chain BTC deposit, provided they supply a valid light-client proof. When `deposit_msg.refund_address` is `None`, the caller freely chooses the `refund_address` parameter. The callback (`request_refund_callback`, lines 497–581) verifies only that the output script matches the deposit address derived from `deposit_msg`; it does **not** restrict who may call or what `refund_address` is used.

---

### Impact Explanation

**Medium — Bypass of bridge limits or policies.**

When `refund_timelock_sec == unsafe_refund_timelock_sec`:

- The DAO's extra review window for "unsafe" refund requests (caller-supplied address) is eliminated.
- An attacker who observes an unverified deposit on-chain, reconstructs the depositor's `deposit_msg` (which is derivable from the BTC transaction and the depositor's public NEAR account ID), and submits a refund request pointing to their own BTC address, can execute that refund after the same timelock as a fully pre-authorized refund.
- If both timelocks are `0` (also permitted by `assert_valid()`), the attacker can execute the refund in the same block as the request, giving the DAO zero time to intervene — escalating to potential direct theft of user deposits.

---

### Likelihood Explanation

The defaults (`DEFAULT_REFUND_TIMELOCK_SEC = 2 days`, `DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC = 14 days`) are distinct, so the vulnerability requires a misconfiguration. However:

- `assert_valid()` explicitly permits equality, so no guard prevents an operator from setting them equal (deliberately or by copy-paste error during deployment or a `update_config` call).
- The external report's analogous bug (MCR == SCR in deployment scripts) shows this class of misconfiguration occurs in practice.
- The `ConfigUpdate::apply()` path (`config.rs` lines 266–301) also calls `assert_valid()` after applying changes, meaning a live update can introduce the equality at any time post-deployment.

---

### Recommendation

Change the validation in `Config::assert_valid()` from `<=` to `<`:

```rust
// Before (allows equality — unsafe):
require!(
    self.refund_timelock_sec <= self.unsafe_refund_timelock_sec,
    "refund_timelock_sec must be <= unsafe_refund_timelock_sec"
);

// After (strict ordering — enforces the intended extra review window):
require!(
    self.refund_timelock_sec < self.unsafe_refund_timelock_sec,
    "refund_timelock_sec must be strictly less than unsafe_refund_timelock_sec"
);
```

Additionally, enforce a minimum non-zero value for `refund_timelock_sec` to prevent both being set to `0`.

---

### Proof of Concept

1. Operator calls `update_config` setting `refund_timelock_sec = T` and `unsafe_refund_timelock_sec = T` (equal). `assert_valid()` accepts this.
2. Alice deposits BTC with `deposit_msg = { recipient_id: "alice.near", refund_address: None }`. The deposit is on-chain but not yet verified by the bridge.
3. Bob observes Alice's BTC transaction on-chain, reconstructs her `deposit_msg` (her NEAR account ID is public), and calls `request_refund(deposit_msg, refund_address="bob_btc_addr", tx_bytes, vout, proof)`.
4. The light client verifies the transaction; `request_refund_callback` confirms the output script matches Alice's deposit address and stores the refund request with `refund_address = "bob_btc_addr"`.
5. After exactly `T` seconds — the same wait as a pre-authorized refund — Bob calls `execute_refund`. The DAO had only `T` time to detect and reject, identical to the "safe" path, instead of the intended longer `unsafe_refund_timelock_sec` window.
6. The refund transaction is built paying `bob_btc_addr`; Alice's deposit is redirected to Bob. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```

**File:** contracts/satoshi-bridge/src/config.rs (L154-157)
```rust
        require!(
            self.refund_timelock_sec <= self.unsafe_refund_timelock_sec,
            "refund_timelock_sec must be <= unsafe_refund_timelock_sec"
        );
```

**File:** contracts/satoshi-bridge/src/config.rs (L266-301)
```rust
    pub fn apply(self, config: &mut Config) {
        macro_rules! set_if_some {
            ($field:ident) => {
                if let Some(v) = self.$field {
                    config.$field = v;
                }
            };
        }
        set_if_some!(btc_light_client_account_id);
        set_if_some!(nbtc_account_id);
        set_if_some!(confirmations_delta);
        set_if_some!(extra_msg_confirmations_delta);
        set_if_some!(deposit_bridge_fee);
        set_if_some!(withdraw_bridge_fee);
        set_if_some!(min_deposit_amount);
        set_if_some!(min_withdraw_amount);
        set_if_some!(min_change_amount);
        set_if_some!(max_change_amount);
        set_if_some!(min_btc_gas_fee);
        set_if_some!(max_btc_gas_fee);
        set_if_some!(max_withdrawal_input_number);
        set_if_some!(max_change_number);
        set_if_some!(max_active_utxo_management_input_number);
        set_if_some!(max_active_utxo_management_output_number);
        set_if_some!(active_management_lower_limit);
        set_if_some!(active_management_upper_limit);
        set_if_some!(passive_management_lower_limit);
        set_if_some!(passive_management_upper_limit);
        set_if_some!(rbf_num_limit);
        set_if_some!(max_btc_tx_pending_sec);
        set_if_some!(unhealthy_utxo_amount);
        set_if_some!(refund_timelock_sec);
        set_if_some!(unsafe_refund_timelock_sec);

        config.assert_valid();
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L137-184)
```rust
    pub(crate) fn internal_request_refund(
        &self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<u128>,
    ) -> Promise {
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }

        let transaction =
            crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
        let tx_id = transaction.compute_txid().to_string();

        let config = self.internal_config();
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);

        self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
            confirmations,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_REQUEST_REFUND_CALLBACK)
                .request_refund_callback(deposit_msg, refund_address, tx_bytes, vout, gas_fee),
        )
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L216-227)
```rust
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
```
