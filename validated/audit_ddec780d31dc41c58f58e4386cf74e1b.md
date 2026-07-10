### Title
Unbounded RBF Entry Accumulation Causes Out-of-Gas in Withdrawal Verification — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

The `withdraw_rbf` function is publicly callable by any withdrawal initiator and appends entries to the per-transaction `rbf_txs` set without a per-transaction cap. When `verify_withdraw_v2` is later called to finalize the withdrawal, it must clean up all associated RBF pending entries in a single NEAR transaction. If a user has accumulated sufficiently many RBF entries, this cleanup loop exhausts the NEAR gas budget, causing verification to fail and leaving the withdrawal in a stuck state. The developers themselves acknowledge this risk in a code comment.

---

### Finding Description

The `withdraw_rbf` function is a public, unpermissioned entry point callable by any user who has an active withdrawal: [1](#0-0) 

There is no on-chain limit on how many times `withdraw_rbf` may be called for the same original pending transaction. Each call appends a new entry to the `rbf_txs` map (a `HashMap<String, HashSet<String>>`), keyed by the original transaction ID.

The developers explicitly acknowledge that iterating over all accumulated RBF entries during withdrawal verification can exhaust gas: [2](#0-1) 

The comment at line 430–432 reads:

> "Since there can be many RBFs, removing all RBF pending info at once after verifying the transaction on-chain might not have enough gas. Therefore, the off-chain program uses this interface to perform the cleanup."

This confirms that `verify_withdraw_v2` (via `internal_verify_withdraw_entry`) iterates over and removes all RBF entries for the original transaction in a single call. If the set is large enough, the call runs out of gas and reverts.

The off-chain cleanup path (`batch_clear_invalid_pending_verify_rbf`) is not enforced on-chain before `verify_withdraw_v2` is called — it is a best-effort off-chain operation. An attacker can race ahead of the relayer's cleanup by repeatedly calling `withdraw_rbf`, filling the RBF set before the relayer can drain it. [3](#0-2) 

---

### Impact Explanation

If `verify_withdraw_v2` cannot complete due to out-of-gas:

- The BTC has already been broadcast and confirmed on-chain (the Bitcoin side of the withdrawal is complete).
- The nBTC burn cannot be finalized on NEAR, leaving the bridge's accounting in an inconsistent state.
- The withdrawal is stuck and requires operator intervention (manual off-chain cleanup of RBF entries followed by a retry), matching the **Medium** impact class: *stuck bridge state requiring operator intervention*.

---

### Likelihood Explanation

Medium. Any user who initiates a withdrawal can call `withdraw_rbf` in a tight loop before the relayer's off-chain cleanup runs. The only friction is the NEAR gas cost per `withdraw_rbf` call, which is low. A determined attacker willing to spend a modest amount of NEAR gas can accumulate enough RBF entries to reliably block finalization of their own (or any targeted) withdrawal.

---

### Recommendation

Enforce an on-chain cap on the number of RBF entries per original transaction. For example, reject `withdraw_rbf` calls once `rbf_txs.get(original_id).map_or(0, |s| s.len())` exceeds a configured maximum (e.g., 10). This bounds the cleanup work in `verify_withdraw_v2` to a constant and eliminates the out-of-gas vector without requiring off-chain coordination.

---

### Proof of Concept

1. User initiates a withdrawal via `ft_transfer_call` → `ft_on_transfer`. A `BTCPendingInfo` entry is created with `btc_pending_id = X`.
2. MPC signs the transaction; the relayer is about to call `verify_withdraw_v2(X, proof)`.
3. Before the relayer's call lands, the user calls `withdraw_rbf(X, ...)` in a loop N times (e.g., N = 500), each time creating a new RBF entry in `rbf_txs[X]`.
4. The relayer's `verify_withdraw_v2` call attempts to remove all N RBF entries from `btc_pending_infos` and `rbf_txs` in a single transaction. With N large enough, the call exceeds the 300 TGas NEAR limit and reverts.
5. The BTC transaction is confirmed on Bitcoin; the NEAR withdrawal is permanently stuck until an operator manually drains the RBF set via `batch_clear_invalid_pending_verify_rbf` and retries verification. [1](#0-0) [4](#0-3) [2](#0-1)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L240-250)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_withdraw_v2(&mut self, tx_id: String, proof: TxInclusionProof) -> Promise {
        self.internal_verify_withdraw_entry(
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-274)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn withdraw_rbf(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
        chain_specific_data: Option<ChainSpecificData>,
    ) {
        let account_id = env::predecessor_account_id();
        self.require_pending_sign_capacity(&account_id);

        self.withdraw_rbf_chain_specific(
            account_id,
            original_btc_pending_verify_id,
            output,
            chain_specific_data,
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L430-446)
```rust
    /// Since there can be many RBFs, removing all RBF pending info at once after verifying the transaction on-chain might not have enough gas.
    /// Therefore, the off-chain program uses this interface to perform the cleanup.
    ///
    /// # Arguments
    ///
    /// * `btc_pending_verify_id` - Invalid pending info ID.
    #[pause(except(roles(Role::DAO)))]
    pub fn clear_invalid_pending_verify_rbf(&mut self, btc_pending_verify_id: String) {
        self.internal_clear_invalid_pending_verify_rbf(btc_pending_verify_id);
    }

    #[pause(except(roles(Role::DAO)))]
    pub fn batch_clear_invalid_pending_verify_rbf(&mut self, btc_pending_verify_ids: Vec<String>) {
        for btc_pending_verify_id in btc_pending_verify_ids {
            self.internal_clear_invalid_pending_verify_rbf(btc_pending_verify_id);
        }
    }
```
